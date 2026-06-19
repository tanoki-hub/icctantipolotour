/* =============================================================
   ICCT School Portal — Database & Auth Layer  (db.js)
   Enhanced version — ES6+, SHA-256, School ID auth, OTP v2
   ============================================================= */

'use strict';

/* ── Debug flag: set to true during development ── */
const DEBUG = false;

const log = {
  info:  (...a) => DEBUG && console.log('%c[DB INFO]',  'color:#3b82f6', ...a),
  warn:  (...a) => DEBUG && console.warn('%c[DB WARN]', 'color:#f59e0b', ...a),
  error: (...a) =>          console.error('%c[DB ERR]', 'color:#ef4444', ...a),
  ok:    (...a) => DEBUG && console.log('%c[DB OK]',    'color:#22c55e', ...a),
};

/* ── Storage keys ── */
const KEYS = {
  USERS:    'icct_users',
  OTPS:     'icct_otps',
  STUDENTS: 'icct_students',
  SESSION:  'icct_session',
  OTP_META: 'icct_otp_meta',   // attempt tracking
};

/* ── Constants ── */
const OTP_TTL_MS        = 5 * 60 * 1000;   // 5 minutes
const OTP_MAX_ATTEMPTS  = 3;
const SESSION_TTL_MS    = 30 * 60 * 1000;  // 30 min inactivity
const SCHOOL_ID_REGEX   = /^[A-Z]{2}\d{9}$/;  // e.g. UA202500000
const ADMIN_ID          = 'ADMIN001';

/* ── Password rules ── */
const PW_RULES = [
  { test: (p) => p.length >= 8,            msg: 'At least 8 characters' },
  { test: (p) => /[A-Z]/.test(p),          msg: 'At least 1 uppercase letter' },
  { test: (p) => /[a-z]/.test(p),          msg: 'At least 1 lowercase letter' },
  { test: (p) => /[0-9]/.test(p),          msg: 'At least 1 number' },
  { test: (p) => /[^A-Za-z0-9]/.test(p),   msg: 'At least 1 special character' },
];

/* ── Courses & year levels for validation ── */
const VALID_COURSES = [
  'BSIT', 'BSCS', 'BSIS', 'BSCpE', 'BSECE',
  'BSA', 'BSBA', 'BSHM', 'BSTM', 'BSN',
];
const VALID_YEAR_LEVELS = ['1st Year', '2nd Year', '3rd Year', '4th Year'];

/* ============================================================
   UTILITIES
   ============================================================ */

/** Generate a cryptographically random UUID-like string */
function genUID() {
  return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11)
    .replace(/[018]/g, (c) =>
      (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4))).toString(16)
    );
}

/** SHA-256 hash via Web Crypto API — returns hex string */
async function sha256(text) {
  try {
    const buf = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(text)
    );
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  } catch (err) {
    log.error('sha256 failed', err);
    throw new Error('Hashing unavailable in this environment.');
  }
}

/** Strip HTML tags and trim whitespace — basic XSS guard */
function sanitize(value) {
  if (typeof value !== 'string') return '';
  return value.replace(/<[^>]*>/g, '').trim();
}

/** Safe JSON read from localStorage — returns fallback on corrupt data */
function safeRead(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (raw === null) return fallback;
    return JSON.parse(raw);
  } catch {
    log.warn(`safeRead: corrupt data at "${key}", returning fallback`);
    return fallback;
  }
}

/** Safe JSON write to localStorage */
function safeWrite(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch (err) {
    log.error(`safeWrite: failed for "${key}"`, err);
    return false;
  }
}

/* ============================================================
   VALIDATION HELPERS  (exported for use in form UI)
   ============================================================ */

const Validate = {
  /** Returns array of failed rule messages; empty = valid */
  password(pw) {
    return PW_RULES.filter((r) => !r.test(pw)).map((r) => r.msg);
  },

  /** Returns true if School ID matches the expected format OR is the admin ID */
  schoolId(id) {
    return id === ADMIN_ID || SCHOOL_ID_REGEX.test(id);
  },

  /** Returns error string or null */
  course(course) {
    return VALID_COURSES.includes(course) ? null : `Course must be one of: ${VALID_COURSES.join(', ')}`;
  },

  yearLevel(year) {
    return VALID_YEAR_LEVELS.includes(year) ? null : `Year level must be one of: ${VALID_YEAR_LEVELS.join(', ')}`;
  },
};

/* ============================================================
   DATABASE OBJECT
   ============================================================ */

const DB = {

  /* ----------------------------------------------------------
     USER MANAGEMENT
     ---------------------------------------------------------- */

  getUsers() {
    const users = safeRead(KEYS.USERS, []);
    return Array.isArray(users) ? users : [];
  },

  _saveUsers(users) {
    safeWrite(KEYS.USERS, users);
  },

  findUserById(schoolId) {
    return this.getUsers().find((u) => u.schoolId === schoolId) || null;
  },

  /**
   * Register a new user.
   * @param {{ name, schoolId, password, role }} params
   * @returns {{ ok: boolean, msg?: string }}
   */
  async registerUser({ name, schoolId, password, role = 'student' }) {
    try {
      const cleanName     = sanitize(name);
      const cleanId       = sanitize(schoolId).toUpperCase();
      const cleanPassword = sanitize(password);

      if (!cleanName)                      return { ok: false, msg: 'Name is required.' };
      if (!Validate.schoolId(cleanId))     return { ok: false, msg: 'Invalid School ID format (e.g. UA202500000).' };

      const pwErrors = Validate.password(cleanPassword);
      if (pwErrors.length)                 return { ok: false, msg: pwErrors[0] };

      const users = this.getUsers();
      if (users.find((u) => u.schoolId === cleanId)) {
        return { ok: false, msg: 'School ID already registered.' };
      }

      const hashed = await sha256(cleanPassword);
      const newUser = {
        uid:        genUID(),
        schoolId:   cleanId,
        name:       cleanName,
        password:   hashed,
        role:       ['student', 'admin', 'faculty'].includes(role) ? role : 'student',
        createdAt:  new Date().toISOString(),
        isAdmin:    false,
      };

      users.push(newUser);
      this._saveUsers(users);
      log.ok('User registered:', cleanId);
      return { ok: true };

    } catch (err) {
      log.error('registerUser', err);
      return { ok: false, msg: 'Registration failed. Please try again.' };
    }
  },

  /**
   * Validate login credentials.
   * @returns {{ ok: boolean, user?: object, msg?: string }}
   */
  async validateUser(schoolId, password) {
    try {
      const cleanId = sanitize(schoolId).toUpperCase();
      const user    = this.findUserById(cleanId);

      if (!user) return { ok: false, msg: 'School ID not found.' };

      const hashed = await sha256(sanitize(password));
      if (user.password !== hashed) return { ok: false, msg: 'Incorrect password.' };

      log.ok('Validated:', cleanId);
      return { ok: true, user };

    } catch (err) {
      log.error('validateUser', err);
      return { ok: false, msg: 'Login failed. Please try again.' };
    }
  },

  /** Prevent admin account from being deleted or modified by non-admins */
  isProtectedUser(schoolId) {
    return schoolId === ADMIN_ID;
  },

  /* ----------------------------------------------------------
     SESSION MANAGEMENT
     ---------------------------------------------------------- */

  setSession(user) {
    const session = {
      uid:       user.uid,
      schoolId:  user.schoolId,
      name:      user.name,
      role:      user.role,
      isAdmin:   user.isAdmin || user.schoolId === ADMIN_ID,
      loginAt:   Date.now(),
      lastActive: Date.now(),
    };
    sessionStorage.setItem(KEYS.SESSION, JSON.stringify(session));
    log.info('Session started:', session.schoolId);
  },

  getSession() {
    try {
      const raw = sessionStorage.getItem(KEYS.SESSION);
      if (!raw) return null;

      const session = JSON.parse(raw);

      /* Inactivity check */
      if (Date.now() - session.lastActive > SESSION_TTL_MS) {
        log.warn('Session expired due to inactivity.');
        this.clearSession();
        return null;
      }

      /* Refresh lastActive timestamp */
      session.lastActive = Date.now();
      sessionStorage.setItem(KEYS.SESSION, JSON.stringify(session));
      return session;

    } catch {
      this.clearSession();
      return null;
    }
  },

  clearSession() {
    sessionStorage.removeItem(KEYS.SESSION);
    sessionStorage.removeItem('icct_otp_target');
    log.info('Session cleared.');
  },

  /**
   * Guard protected pages — call at top of each dashboard script.
   * Redirects to login if unauthenticated; optionally enforces role.
   */
  requireAuth(requiredRole = null) {
    const session = this.getSession();
    if (!session) {
      window.location.replace('index.html');
      return null;
    }
    if (requiredRole && session.role !== requiredRole && !session.isAdmin) {
      window.location.replace('index.html');
      return null;
    }
    return session;
  },

  /* ----------------------------------------------------------
     OTP SYSTEM
     ---------------------------------------------------------- */

  /** Generate a secure 6-digit OTP */
  generateOTP() {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return String(100000 + (arr[0] % 900000));
  },

  saveOTP(schoolId, code) {
    const otps = safeRead(KEYS.OTPS, {});
    otps[schoolId] = {
      code,
      expires:  Date.now() + OTP_TTL_MS,
      issuedAt: Date.now(),
    };
    safeWrite(KEYS.OTPS, otps);

    /* Reset attempt counter */
    const meta = safeRead(KEYS.OTP_META, {});
    meta[schoolId] = { attempts: 0, lockedUntil: null };
    safeWrite(KEYS.OTP_META, meta);

    log.info('OTP saved for:', schoolId);
  },

  /**
   * Return the active OTP entry for a school ID.
   */
  getOTPEntry(schoolId) {
    const otps = safeRead(KEYS.OTPS, {});
    return otps[schoolId] || null;
  },

  /**
   * Verify OTP — respects attempt limits and lock state.
   * @returns {{ ok: boolean, msg?: string, locked?: boolean, remaining?: number }}
   */
  verifyOTP(schoolId, code) {
    try {
      const otps = safeRead(KEYS.OTPS, {});
      const meta = safeRead(KEYS.OTP_META, {});
      const entry   = otps[schoolId];
      const tracker = meta[schoolId] || { attempts: 0, lockedUntil: null };

      /* Lock check */
      if (tracker.lockedUntil && Date.now() < tracker.lockedUntil) {
        const remaining = Math.ceil((tracker.lockedUntil - Date.now()) / 1000);
        return { ok: false, locked: true, remaining, msg: `Too many attempts. Try again in ${remaining}s.` };
      }

      if (!entry)                    return { ok: false, msg: 'No OTP found. Please request a new one.' };
      if (Date.now() > entry.expires) {
        delete otps[schoolId];
        safeWrite(KEYS.OTPS, otps);
        return { ok: false, msg: 'OTP expired. Please request a new one.' };
      }

      if (entry.code !== String(code).trim()) {
        tracker.attempts += 1;
        if (tracker.attempts >= OTP_MAX_ATTEMPTS) {
          tracker.lockedUntil = Date.now() + 2 * 60 * 1000; // 2-min lock
          tracker.attempts    = 0;
          meta[schoolId] = tracker;
          safeWrite(KEYS.OTP_META, meta);
          return { ok: false, locked: true, remaining: 120, msg: 'Too many failed attempts. Account locked for 2 minutes.' };
        }
        meta[schoolId] = tracker;
        safeWrite(KEYS.OTP_META, meta);
        return { ok: false, msg: `Invalid OTP. ${OTP_MAX_ATTEMPTS - tracker.attempts} attempt(s) remaining.` };
      }

      /* Success — clean up */
      delete otps[schoolId];
      delete meta[schoolId];
      safeWrite(KEYS.OTPS, otps);
      safeWrite(KEYS.OTP_META, meta);
      log.ok('OTP verified for:', schoolId);
      return { ok: true };

    } catch (err) {
      log.error('verifyOTP', err);
      return { ok: false, msg: 'Verification failed. Please try again.' };
    }
  },

  /** Returns seconds remaining on a live OTP, or 0 if expired/absent */
  getOTPTimeRemaining(schoolId) {
    const otps  = safeRead(KEYS.OTPS, {});
    const entry = otps[schoolId];
    if (!entry) return 0;
    const remaining = Math.max(0, Math.ceil((entry.expires - Date.now()) / 1000));
    return remaining;
  },

  /** Resend: only allowed if previous OTP is expired or absent */
  canResendOTP(schoolId) {
    return this.getOTPTimeRemaining(schoolId) === 0;
  },

  /* ----------------------------------------------------------
     STUDENT MANAGEMENT
     ---------------------------------------------------------- */

  getStudents() {
    const students = safeRead(KEYS.STUDENTS, []);
    return Array.isArray(students) ? students : [];
  },

  _saveStudents(students) {
    safeWrite(KEYS.STUDENTS, students);
  },

  /**
   * Add a new student record.
   * @param {{ name, studentId, course, yearLevel, profileImage? }} student
   */
  addStudent(student) {
    try {
      const cleanId     = sanitize(student.studentId || '').toUpperCase();
      const cleanName   = sanitize(student.name || '');
      const cleanCourse = sanitize(student.course || '');
      const cleanYear   = sanitize(student.yearLevel || '');

      if (!cleanName)   return { ok: false, msg: 'Student name is required.' };
      if (!cleanId)     return { ok: false, msg: 'Student ID is required.' };
      if (Validate.course(cleanCourse))     return { ok: false, msg: Validate.course(cleanCourse) };
      if (Validate.yearLevel(cleanYear))    return { ok: false, msg: Validate.yearLevel(cleanYear) };

      const students = this.getStudents();
      if (students.find((s) => s.studentId === cleanId)) {
        return { ok: false, msg: 'Student ID already exists.' };
      }

      const newStudent = {
        id:           genUID(),
        studentId:    cleanId,
        name:         cleanName,
        course:       cleanCourse,
        yearLevel:    cleanYear,
        status:       'pending',
        profileImage: student.profileImage || null,
        enrolledAt:   new Date().toISOString(),
        updatedAt:    new Date().toISOString(),
      };

      students.push(newStudent);
      this._saveStudents(students);
      log.ok('Student added:', cleanId);
      return { ok: true, student: newStudent };

    } catch (err) {
      log.error('addStudent', err);
      return { ok: false, msg: 'Failed to add student.' };
    }
  },

  updateStudent(id, data) {
    try {
      const students = this.getStudents().map((s) => {
        if (s.id !== id) return s;
        const updated = { ...s, ...data, updatedAt: new Date().toISOString() };
        /* Sanitize mutable fields */
        if (data.name)      updated.name      = sanitize(data.name);
        if (data.course)    updated.course    = sanitize(data.course);
        if (data.yearLevel) updated.yearLevel = sanitize(data.yearLevel);
        if (data.status)    updated.status    = ['pending', 'approved', 'rejected', 'inactive'].includes(data.status)
                                                 ? data.status : s.status;
        return updated;
      });
      this._saveStudents(students);
      return { ok: true };
    } catch (err) {
      log.error('updateStudent', err);
      return { ok: false, msg: 'Failed to update student.' };
    }
  },

  deleteStudent(id) {
    this._saveStudents(this.getStudents().filter((s) => s.id !== id));
    log.info('Student deleted:', id);
  },

  approveStudent(id) {
    return this.updateStudent(id, { status: 'approved' });
  },

  /**
   * Search students across multiple fields.
   * @param {string} query
   * @param {{ status?, course?, yearLevel?, sortBy?, sortDir? }} options
   */
  searchStudents(query = '', options = {}) {
    let students = this.getStudents();
    const q = sanitize(query).toLowerCase();

    /* Text search */
    if (q) {
      students = students.filter((s) =>
        (s.name       || '').toLowerCase().includes(q) ||
        (s.studentId  || '').toLowerCase().includes(q) ||
        (s.course     || '').toLowerCase().includes(q) ||
        (s.yearLevel  || '').toLowerCase().includes(q) ||
        (s.status     || '').toLowerCase().includes(q)
      );
    }

    /* Filter by status */
    if (options.status) {
      students = students.filter((s) => s.status === options.status);
    }

    /* Filter by course */
    if (options.course) {
      students = students.filter((s) => s.course === options.course);
    }

    /* Filter by year level */
    if (options.yearLevel) {
      students = students.filter((s) => s.yearLevel === options.yearLevel);
    }

    /* Sorting */
    const sortBy  = options.sortBy  || 'enrolledAt';
    const sortDir = options.sortDir === 'asc' ? 1 : -1;

    students.sort((a, b) => {
      const va = (a[sortBy] || '').toString().toLowerCase();
      const vb = (b[sortBy] || '').toString().toLowerCase();
      return va < vb ? -sortDir : va > vb ? sortDir : 0;
    });

    return students;
  },

  /* ----------------------------------------------------------
     ADMIN UTILITIES
     ---------------------------------------------------------- */

  /** Returns true if current session belongs to an admin */
  isAdmin() {
    const session = this.getSession();
    return session ? session.isAdmin === true : false;
  },

  /** Initialize the default admin account (idempotent) */
  async initializeDefaultAdmin() {
    try {
      const users = this.getUsers();
      const adminExists = users.find((u) => u.schoolId === ADMIN_ID);

      if (!adminExists) {
        const hashed = await sha256('Admin123!');
        const admin = {
          uid:       genUID(),
          schoolId:  ADMIN_ID,
          name:      'ICCT Administrator',
          password:  hashed,
          role:      'admin',
          isAdmin:   true,
          createdAt: new Date().toISOString(),
        };
        users.push(admin);
        this._saveUsers(users);
        log.ok('Default admin account created.');
      } else {
        log.info('Admin account already exists.');
      }
    } catch (err) {
      log.error('initializeDefaultAdmin', err);
    }
  },

  /* ----------------------------------------------------------
     RESET / DEBUG
     ---------------------------------------------------------- */

  resetAllData() {
    Object.values(KEYS).forEach((k) => {
      localStorage.removeItem(k);
      sessionStorage.removeItem(k);
    });
    sessionStorage.removeItem('icct_otp_target');
    log.warn('⚠ All data has been reset.');
  },
};

/* ── Boot ── */
DB.initializeDefaultAdmin();

/* ── Exports for modules or inline script access ── */
if (typeof module !== 'undefined') module.exports = { DB, Validate, VALID_COURSES, VALID_YEAR_LEVELS };