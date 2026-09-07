import "dotenv/config";
import express from "express";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const DATA_FILE = path.join(__dirname, "data", "site-config.json");
const ACTIVITIES_FILE = path.join(__dirname, "data", "student-activities.json");
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");

// Matches the pytdsbconnects repository.
const API_URL = "https://zappsmaprd.tdsb.on.ca/";
const CLIENT_INFO = "pytdsbconnects||||0.0.0||2147483647|";
const SECRET = process.env.SESSION_SECRET || "CHANGE-THIS-IN-PRODUCTION";
const KEY = crypto.createHash("sha256").update(SECRET).digest();

app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

function encrypt(data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), "utf8"),
    cipher.final()
  ]);
  return [iv, cipher.getAuthTag(), encrypted].map(x => x.toString("base64url")).join(".");
}

function decrypt(value) {
  const [iv, tag, encrypted] = String(value || "").split(".");
  if (!iv || !tag || !encrypted) throw new Error("Invalid session");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    KEY,
    Buffer.from(iv, "base64url")
  );
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(encrypted, "base64url")),
    decipher.final()
  ]).toString("utf8"));
}

function cookieValue(req, name) {
  const part = (req.headers.cookie || "")
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="));
  return part ? part.slice(name.length + 1) : null;
}

function getSession(req) {
  const value = cookieValue(req, "tdsb_session");
  if (!value) return null;
  try {
    const session = decrypt(value);
    if (!session.createdAt || Date.now() - session.createdAt > 24 * 60 * 60 * 1000) return null;
    return session;
  } catch {
    return null;
  }
}

function setSession(res, session) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  const value = encrypt({ ...session, createdAt: Date.now() });
  res.setHeader(
    "Set-Cookie",
    `tdsb_session=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400${secure}`
  );
}

function clearSession(res) {
  res.setHeader(
    "Set-Cookie",
    "tdsb_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
  );
}

async function request(url, options = {}) {
  return fetch(url, {
    ...options,
    headers: {
      "X-Client-App-Info": CLIENT_INFO,
      ...(options.headers || {})
    }
  });
}

async function readJson(response) {
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    const message =
      data.error_description ||
      data.errorDescription ||
      data.message ||
      data.Message ||
      `TDSB returned HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.responseDebug = {
      status: response.status,
      ok: response.ok,
      contentType: response.headers.get('content-type') || '',
      bytes: Buffer.byteLength(text, 'utf8'),
      topLevelType: Array.isArray(data) ? 'array' : typeof data,
      topLevelKeys: data && typeof data === 'object' && !Array.isArray(data) ? Object.keys(data) : [],
      rawResponse: text.slice(0, 20000)
    };
    throw error;
  }
  return data;
}

async function readJsonWithDebug(response) {
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  const debug = {
    status: response.status,
    ok: response.ok,
    contentType: response.headers.get('content-type') || '',
    bytes: Buffer.byteLength(text, 'utf8'),
    topLevelType: Array.isArray(data) ? 'array' : typeof data,
    topLevelKeys: data && typeof data === 'object' && !Array.isArray(data) ? Object.keys(data) : [],
    rawResponse: text.slice(0, 20000)
  };

  if (!response.ok) {
    const message =
      data.error_description ||
      data.errorDescription ||
      data.message ||
      data.Message ||
      `TDSB returned HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.responseDebug = debug;
    throw error;
  }

  return { data, debug };
}

async function refreshAccessToken(session) {
  if (!session.refreshToken) return session;

  const body = new URLSearchParams({
    refresh_token: session.refreshToken,
    grant_type: "refresh_token"
  });

  const response = await request(API_URL + "token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const token = await readJson(response);
  return {
    ...session,
    accessToken: token.access_token,
    refreshToken: token.refresh_token || session.refreshToken,
    tokenExpiresAt: Date.now() + Number(token.expires_in || 0) * 1000
  };
}

async function withFreshToken(req, res) {
  let session = getSession(req);
  if (!session) {
    const error = new Error("Not signed in.");
    error.status = 401;
    throw error;
  }

  // Same behavior as pytdsbconnects: refresh shortly before expiry.
  if (
    session.refreshToken &&
    session.tokenExpiresAt &&
    Date.now() + 30000 >= session.tokenExpiresAt
  ) {
    session = await refreshAccessToken(session);
    setSession(res, session);
  }
  return session;
}

function formatDDMMYYYY(date) {
  return `${String(date.getDate()).padStart(2, "0")}${String(date.getMonth() + 1).padStart(2, "0")}${date.getFullYear()}`;
}

function localDateFromISO(value) {
  const m = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return null;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return Number.isNaN(d.getTime()) ? null : d;
}

function isoDate(date) {
  return `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,"0")}-${String(date.getDate()).padStart(2,"0")}`;
}

// Exact structure used by pytdsbconnects:
// data["CourseTable"] -> item["StudentCourse"] -> fields.
function normalizeCourse(item) {
  const c = item?.StudentCourse || {};
  return {
    studentNumber: item?.StudentNumber ?? "",
    courseKey: item?.CourseKey ?? "",
    courseCode: c.ClassCode ?? "",
    period: c.Period ?? "",
    block: c.Block ?? "",
    teacher: c.TeacherName ?? "",
    teacherEmail: c.TeacherEmail ?? "",
    room: c.RoomNo ?? "",
    schoolCode: c.SchoolCode ?? "",
    date: c.Date ?? "",
    cycleDay: c.CycleDay ?? "",
    startTime: c.StartTime ?? "",
    endTime: c.EndTime ?? "",
    className: c.ClassName ?? "",
    semester: c.Semester ?? "",
    term: c.Term ?? "",
    timeline: c.Timeline ?? "",
    track: c.SchoolYearTrack ?? ""
  };
}

async function fetchOneDay(session, date) {
  const url =
    API_URL +
    `api/TimeTable/GetTimeTable/Student/${encodeURIComponent(session.schoolCode)}/${formatDDMMYYYY(date)}`;

  const response = await request(url, {
    headers: { Authorization: `Bearer ${session.accessToken}` }
  });

  try {
    const result = await readJsonWithDebug(response);
    const data = result.data;
    const rows = Array.isArray(data?.CourseTable) ? data.CourseTable : [];

    return {
      classes: rows.map(normalizeCourse),
      debug: {
        ...result.debug,
        request: { method: 'GET', url },
        courseTableType: Array.isArray(data?.CourseTable) ? 'array' : typeof data?.CourseTable,
        courseTableCount: rows.length,
        responseShape: summarizeShape(data)
      }
    };
  } catch (error) {
    error.debug = {
      ...(error.responseDebug || {}),
      request: { method: 'GET', url },
      error: error.message
    };
    throw error;
  }
}

function summarizeShape(value, depth = 0) {
  if (depth > 2) return Array.isArray(value) ? `[array ${value.length}]` : typeof value;
  if (Array.isArray(value)) {
    return { type: 'array', length: value.length, first: value.length ? summarizeShape(value[0], depth + 1) : null };
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value).slice(0, 40)) out[key] = summarizeShape(item, depth + 1);
    return out;
  }
  return value === null ? 'null' : typeof value;
}


const DEFAULT_CONFIG = {
  settings: { cycleRule: "oddDay1EvenDay2", defaultScheduleId: "regular", defaultGrade: "9", lateStart: { enabled: true, scheduleId: "late-start", pattern: "last2WednesdaysOfMonth" }, lunch: { start: "11:40", end: "12:40", label: "Lunch" } },
  announcements: [],
  schedules: [{ id: "regular", name: "Regular Day", grade: "all", eventStart: "", eventEnd: "", periods: [], lunch: { start: "11:40", end: "12:40", label: "Lunch" } }],
  events: []
};

async function readConfig() {
  try {
    const text = await fs.readFile(DATA_FILE, "utf8");
    return { ...DEFAULT_CONFIG, ...JSON.parse(text) };
  } catch {
    await writeConfig(DEFAULT_CONFIG);
    return structuredClone(DEFAULT_CONFIG);
  }
}

async function writeConfig(config) {
  await fs.mkdir(path.dirname(DATA_FILE), { recursive: true });
  const temp = DATA_FILE + ".tmp";
  await fs.writeFile(temp, JSON.stringify(config, null, 2), "utf8");
  await fs.rename(temp, DATA_FILE);
}

function adminCookie(req) {
  const value = cookieValue(req, "tdsb_admin");
  if (!value) return null;
  try {
    const session = decrypt(value);
    if (session.role !== "admin" || Date.now() - session.createdAt > 12 * 60 * 60 * 1000) return null;
    return session;
  } catch { return null; }
}

function setAdminSession(res) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  const value = encrypt({ role: "admin", createdAt: Date.now() });
  res.setHeader("Set-Cookie", `tdsb_admin=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${secure}`);
}

function clearAdminSession(res) {
  res.setHeader("Set-Cookie", "tdsb_admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
}

function requireAdmin(req, res, next) {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: "Admin panel is disabled. Set ADMIN_PASSWORD in .env." });
  if (!adminCookie(req)) return res.status(401).json({ error: "Admin authentication required." });
  next();
}

function cleanConfig(input) {
  const config = input && typeof input === "object" ? input : {};
  const safe = {
    settings: {
      cycleRule: "oddDay1EvenDay2",
      defaultScheduleId: String(config.settings?.defaultScheduleId || "regular"),
      defaultGrade: String(config.settings?.defaultGrade || "9"),
      lunch: {
        start: String(config.settings?.lunch?.start || "11:40"),
        end: String(config.settings?.lunch?.end || "12:40"),
        label: String(config.settings?.lunch?.label || "Lunch").slice(0, 60)
      },
      lateStart: {
        enabled: config.settings?.lateStart?.enabled !== false,
        scheduleId: String(config.settings?.lateStart?.scheduleId || "late-start"),
        pattern: "last2WednesdaysOfMonth"
      }
    },
    announcements: Array.isArray(config.announcements) ? config.announcements.slice(0, 100).map(a => ({
      id: String(a.id || crypto.randomUUID()), title: String(a.title || "").slice(0, 120), body: String(a.body || "").slice(0, 2000),
      startDate: String(a.startDate || ""), endDate: String(a.endDate || ""), active: a.active !== false
    })) : [],
    schedules: Array.isArray(config.schedules) ? config.schedules.slice(0, 100).map(s => ({
      id: String(s.id || crypto.randomUUID()), name: String(s.name || "Schedule").slice(0, 120), grade: String(s.grade || "all"),
      eventStart: String(s.eventStart || ""), eventEnd: String(s.eventEnd || ""),
      periods: Array.isArray(s.periods) ? s.periods.slice(0, 20).map(p => ({ period: String(p.period || ""), start: String(p.start || ""), end: String(p.end || "") })) : [],
      lunch: { start: String(s.lunch?.start || ""), end: String(s.lunch?.end || ""), label: String(s.lunch?.label || "Lunch").slice(0,60) }
    })) : [],
    events: Array.isArray(config.events) ? config.events.slice(0, 200).map(e => ({
      id: String(e.id || crypto.randomUUID()), name: String(e.name || "Event").slice(0, 120), startDate: String(e.startDate || ""), endDate: String(e.endDate || ""),
      type: String(e.type || "schedule"), grade: String(e.grade || "all"), scheduleId: String(e.scheduleId || ""), announcementId: String(e.announcementId || "")
    })) : []
  };
  if (!safe.schedules.some(s => s.id === safe.settings.defaultScheduleId)) safe.settings.defaultScheduleId = safe.schedules[0]?.id || "";
  return safe;
}

function isoToday() { return new Date().toISOString().slice(0, 10); }
function dateInRange(date, start, end) { return (!start || date >= start) && (!end || date <= end); }

function dateIsLastTwoWednesdaysOfMonth(iso) {
  const m = String(iso || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return false;
  const year = Number(m[1]), month = Number(m[2]) - 1, day = Number(m[3]);
  const d = new Date(year, month, day);
  if (d.getDay() !== 3) return false;
  const lastDay = new Date(year, month + 1, 0).getDate();
  const lastWednesday = lastDay - new Date(year, month, lastDay).getDay() + 3;
  // Normalize the calculation to the Wednesday on/before the month's last day.
  const offset = (new Date(year, month, lastDay).getDay() - 3 + 7) % 7;
  const lastWed = lastDay - offset;
  return day === lastWed || day === lastWed - 7;
}


app.post("/api/admin/login", async (req, res) => {
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: "Set ADMIN_PASSWORD in .env first." });
  const password = String(req.body?.password || "");
  const a = Buffer.from(password);
  const b = Buffer.from(ADMIN_PASSWORD);
  const valid = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!valid) return res.status(401).json({ error: "Invalid admin password." });
  setAdminSession(res);
  res.json({ ok: true });
});

app.post("/api/admin/logout", (req, res) => { clearAdminSession(res); res.json({ ok: true }); });
app.get("/api/admin/session", (req, res) => res.json({ authenticated: !!adminCookie(req) }));

app.get("/api/site-config", async (req, res) => {
  const config = await readConfig();
  const date = String(req.query.date || isoToday());
  const grade = String(req.query.grade || "all");
  const announcements = config.announcements.filter(a => a.active && dateInRange(date, a.startDate, a.endDate));
  const event = [...config.events].reverse().find(e => dateInRange(date, e.startDate, e.endDate) && (e.grade === "all" || e.grade === grade));
  let schedule = null;
  let recurringEvent = null;
  if (event?.scheduleId) schedule = config.schedules.find(s => s.id === event.scheduleId) || null;
  if (!schedule && grade !== "all") schedule = config.schedules.find(s => s.grade === grade && dateInRange(date, s.eventStart, s.eventEnd)) || null;

  const lateStart = config.settings?.lateStart;
  if (!schedule && lateStart?.enabled && lateStart.scheduleId && dateIsLastTwoWednesdaysOfMonth(date)) {
    schedule = config.schedules.find(s => s.id === lateStart.scheduleId) || null;
    if (schedule) recurringEvent = {
      id: "recurring-late-start",
      name: "Late Start",
      grade: "all",
      scheduleId: lateStart.scheduleId,
      recurring: true
    };
  }
  if (!schedule) schedule = config.schedules.find(s => s.id === config.settings.defaultScheduleId) || config.schedules[0] || null;
  res.json({ settings: config.settings, announcements, schedule, event: event || recurringEvent || null });
});

app.get("/api/admin/config", requireAdmin, async (req, res) => res.json(await readConfig()));

// Explicit admin page route. Without this, the Express fallback would serve the student page at /admin.
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});
app.put("/api/admin/config", requireAdmin, async (req, res) => {
  const config = cleanConfig(req.body);
  await writeConfig(config);
  res.json({ ok: true, config });
});

app.post("/api/login", async (req, res) => {
  const studentId = String(req.body.studentId || "").trim();
  const password = String(req.body.password || "");

  if (!/^\d{9}$/.test(studentId)) {
    return res.status(400).json({ error: "Student ID must be exactly 9 digits." });
  }
  if (!password) {
    return res.status(400).json({ error: "Password is required." });
  }

  try {
    const body = new URLSearchParams({
      username: studentId,
      password,
      grant_type: "password"
    });

    const tokenResponse = await request(API_URL + "token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const token = await readJson(tokenResponse);

    const infoResponse = await request(API_URL + "api/Account/GetUserInfo", {
      headers: { Authorization: `Bearer ${token.access_token}` }
    });
    const user = await readJson(infoResponse);

    // Exact school path from pytdsbconnects:
    // User -> SchoolList -> first School -> SchoolCode / SchoolSetting.
    const school = Array.isArray(user?.SchoolList) ? user.SchoolList[0] : null;
    const schoolCode = school?.SchoolCode;

    if (schoolCode === undefined || schoolCode === null || schoolCode === "") {
      throw new Error("TDSB did not return SchoolList[0].SchoolCode for this account.");
    }

    const schoolSetting = school?.SchoolSetting || {};

    const session = {
      studentId,
      accessToken: token.access_token,
      refreshToken: token.refresh_token || null,
      tokenExpiresAt: Date.now() + Number(token.expires_in || 0) * 1000,
      name: user?.UserName || user?.FirstName || "Student",
      schoolCode: String(schoolCode),
      schoolName: school?.SchoolName || "",
      schoolYear: schoolSetting?.CurrentSession || "",
      schoolYearStart: schoolSetting?.SessionStart || "",
      schoolYearEnd: schoolSetting?.SessionEnd || "",
      schoolTrack: schoolSetting?.SchoolYearTrack || ""
    };

    setSession(res, session);

    // Never return tokens or passwords to the browser.
    res.json({
      ok: true,
      name: session.name,
      schoolName: session.schoolName,
      schoolYear: session.schoolYear,
      schoolYearStart: session.schoolYearStart,
      schoolYearEnd: session.schoolYearEnd,
      debug: {
        endpoint: API_URL + "api/Account/GetUserInfo",
        schoolListCount: Array.isArray(user?.SchoolList) ? user.SchoolList.length : 0,
        schoolCode: session.schoolCode,
        schoolName: session.schoolName,
        schoolYear: session.schoolYear,
        schoolYearStart: session.schoolYearStart,
        schoolYearEnd: session.schoolYearEnd,
        schoolTrack: session.schoolTrack,
        userInfoKeys: user && typeof user === 'object' ? Object.keys(user) : [],
        firstSchoolKeys: school && typeof school === 'object' ? Object.keys(school) : [],
        schoolSettingKeys: schoolSetting && typeof schoolSetting === 'object' ? Object.keys(schoolSetting) : []
      }
    });
  } catch (error) {
    console.error("TDSB login failed:", error.message);
    res.status(error.status === 400 || error.status === 401 ? 401 : 502).json({
      error: error.message || "Unable to sign in."
    });
  }
});

app.get("/api/session", (req, res) => {
  const session = getSession(req);
  if (!session) return res.json({ authenticated: false });

  res.json({
    authenticated: true,
    name: session.name,
    schoolName: session.schoolName,
    schoolYear: session.schoolYear,
    schoolYearStart: session.schoolYearStart,
    schoolYearEnd: session.schoolYearEnd
  });
});


async function readActivities() {
  try {
    const text = await fs.readFile(ACTIVITIES_FILE, "utf8");
    const data = JSON.parse(text);
    return data && typeof data === "object" ? data : {};
  } catch {
    await fs.mkdir(path.dirname(ACTIVITIES_FILE), { recursive: true });
    await fs.writeFile(ACTIVITIES_FILE, "{}", "utf8");
    return {};
  }
}

async function writeActivities(data) {
  await fs.mkdir(path.dirname(ACTIVITIES_FILE), { recursive: true });
  const temp = ACTIVITIES_FILE + ".tmp";
  await fs.writeFile(temp, JSON.stringify(data, null, 2), "utf8");
  await fs.rename(temp, ACTIVITIES_FILE);
}

function cleanActivity(a) {
  const placement = ["before", "during", "after", "weekend"].includes(String(a?.placement)) ? String(a.placement) : "after";
  return {
    id: String(a?.id || crypto.randomUUID()),
    title: String(a?.title || "Activity").slice(0, 120),
    location: String(a?.location || "").slice(0, 120),
    date: String(a?.date || ""),
    startTime: String(a?.startTime || ""),
    endTime: String(a?.endTime || ""),
    placement,
    notes: String(a?.notes || "").slice(0, 500)
  };
}

function validISODate(value) { return /^\d{4}-\d{2}-\d{2}$/.test(String(value || "")); }

app.get("/api/activities", async (req, res) => {
  const session = getSession(req);
  if (!session?.studentId) return res.status(401).json({ error: "Not signed in." });
  const all = await readActivities();
  const activities = Array.isArray(all[session.studentId]) ? all[session.studentId] : [];
  const date = String(req.query.date || "");
  res.json({ activities: date ? activities.filter(a => a.date === date) : activities });
});

app.post("/api/activities", async (req, res) => {
  const session = getSession(req);
  if (!session?.studentId) return res.status(401).json({ error: "Not signed in." });
  const activity = cleanActivity(req.body);
  if (!activity.title || !validISODate(activity.date)) return res.status(400).json({ error: "Title and a valid date are required." });
  const date = localDateFromISO(activity.date);
  if (!date) return res.status(400).json({ error: "Invalid activity date." });
  const isWeekend = date.getDay() === 0 || date.getDay() === 6;
  if (activity.placement === "weekend" && !isWeekend) return res.status(400).json({ error: "Weekend activities must be on Saturday or Sunday." });
  if (activity.placement !== "weekend" && isWeekend) return res.status(400).json({ error: "Before/during/after-school activities must be on a school-day date." });
  const all = await readActivities();
  const list = Array.isArray(all[session.studentId]) ? all[session.studentId] : [];
  list.push(activity);
  all[session.studentId] = list.slice(-200);
  await writeActivities(all);
  res.status(201).json({ ok: true, activity });
});

app.put("/api/activities/:id", async (req, res) => {
  const session = getSession(req);
  if (!session?.studentId) return res.status(401).json({ error: "Not signed in." });
  const all = await readActivities();
  const list = Array.isArray(all[session.studentId]) ? all[session.studentId] : [];
  const i = list.findIndex(a => a.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: "Activity not found." });
  const activity = cleanActivity({ ...list[i], ...req.body, id: list[i].id });
  if (!activity.title || !validISODate(activity.date)) return res.status(400).json({ error: "Title and a valid date are required." });
  const date = localDateFromISO(activity.date);
  const isWeekend = date && (date.getDay() === 0 || date.getDay() === 6);
  if (activity.placement === "weekend" && !isWeekend) return res.status(400).json({ error: "Weekend activities must be on Saturday or Sunday." });
  if (activity.placement !== "weekend" && isWeekend) return res.status(400).json({ error: "Before/during/after-school activities must be on a school-day date." });
  list[i] = activity;
  all[session.studentId] = list;
  await writeActivities(all);
  res.json({ ok: true, activity });
});

app.delete("/api/activities/:id", async (req, res) => {
  const session = getSession(req);
  if (!session?.studentId) return res.status(401).json({ error: "Not signed in." });
  const all = await readActivities();
  const list = Array.isArray(all[session.studentId]) ? all[session.studentId] : [];
  all[session.studentId] = list.filter(a => a.id !== req.params.id);
  await writeActivities(all);
  res.json({ ok: true });
});

app.get("/api/timetable", async (req, res) => {
  try {
    const session = await withFreshToken(req, res);
    const date = localDateFromISO(req.query.date);

    if (!date) {
      return res.status(400).json({
        error: "Use a date in YYYY-MM-DD format."
      });
    }

    const result = await fetchOneDay(session, date);
    res.json({
      date: isoDate(date),
      classes: result.classes,
      debug: result.debug
    });
  } catch (error) {
    console.error("Timetable request failed:", error.message);
    res.status(error.status || 502).json({
      error: error.message || "Unable to load timetable."
    });
  }
});

app.get("/api/timetable/week", async (req, res) => {
  try {
    const session = await withFreshToken(req, res);
    const start = localDateFromISO(req.query.start);

    if (!start) {
      return res.status(400).json({ error: "Use start=YYYY-MM-DD." });
    }

    const days = Array.from({ length: 7 }, (_, i) => {
      const d = new Date(start);
      d.setDate(start.getDate() + i);
      return d;
    });

    // pytdsbconnects makes one exact date request. We do the same,
    // in parallel for fast week navigation.
    const results = await Promise.all(
      days.map(async date => {
        const dateKey = isoDate(date);
        try {
          const result = await fetchOneDay(session, date);
          return { date: dateKey, classes: result.classes, debug: result.debug };
        } catch (error) {
          return {
            date: dateKey,
            classes: [],
            debug: error.debug || error.responseDebug || { error: error.message },
            error: error.message || 'Unable to load this date.'
          };
        }
      })
    );

    res.json({
      start: isoDate(start),
      days: results,
      debug: {
        endpointPattern: API_URL + 'api/TimeTable/GetTimeTable/Student/{SchoolCode}/{DDMMYYYY}',
        schoolCode: session.schoolCode,
        requestedDates: results.map(x => x.date),
        successfulDays: results.filter(x => !x.error).length,
        failedDays: results.filter(x => x.error).length,
        totalClasses: results.reduce((n, x) => n + (x.classes?.length || 0), 0)
      }
    });
  } catch (error) {
    console.error("Week request failed:", error.message);
    res.status(error.status || 502).json({
      error: error.message || "Unable to load timetable week.",
      debug: error.debug || error.responseDebug || null
    });
  }
});

app.post("/api/logout", (req, res) => {
  clearSession(res);
  res.json({ ok: true });
});

// Express 5-safe fallback.
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`TDSB Timetable running at http://localhost:${PORT}`);
});
