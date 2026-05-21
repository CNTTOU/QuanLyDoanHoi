import { createSign } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const TOKEN_URL = "https://oauth2.googleapis.com/token";
const IDENTITY_TOOLKIT_URL =
  "https://identitytoolkit.googleapis.com/v1/accounts:lookup";
const FIRESTORE_SCOPE =
  "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/cloud-platform";

const envFilesLoaded = new Set();
const accessTokenCache = new Map();

function loadEnvFile(filePath) {
  if (envFilesLoaded.has(filePath) || !existsSync(filePath)) return;
  envFilesLoaded.add(filePath);
  const lines = readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
    const [key, ...valueParts] = trimmed.split("=");
    if (process.env[key]) continue;
    process.env[key] = valueParts.join("=").trim().replace(/^['"]|['"]$/g, "");
  }
}

function base64Url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signJwt(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: serviceAccount.client_email,
    scope: FIRESTORE_SCOPE,
    aud: TOKEN_URL,
    exp: now + 3600,
    iat: now,
  };
  const unsigned = `${base64Url(JSON.stringify(header))}.${base64Url(
    JSON.stringify(payload),
  )}`;
  const signature = createSign("RSA-SHA256")
    .update(unsigned)
    .sign(serviceAccount.private_key);
  return `${unsigned}.${base64Url(signature)}`;
}

function signFirebaseCustomToken(serviceAccount, uid, claims = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: serviceAccount.client_email,
    sub: serviceAccount.client_email,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now,
    exp: now + 3600,
    uid,
    claims,
  };
  const unsigned = `${base64Url(JSON.stringify(header))}.${base64Url(
    JSON.stringify(payload),
  )}`;
  const signature = createSign("RSA-SHA256")
    .update(unsigned)
    .sign(serviceAccount.private_key);
  return `${unsigned}.${base64Url(signature)}`;
}

function loadServiceAccount(source) {
  const trimmed = String(source ?? "").trim();
  if (trimmed.startsWith("{")) return JSON.parse(trimmed);
  return JSON.parse(readFileSync(source, "utf8"));
}

async function getAccessToken(serviceAccountSource) {
  const cached = accessTokenCache.get(serviceAccountSource);
  if (cached && cached.expiresAt > Date.now() + 60_000) return cached.token;

  const serviceAccount = loadServiceAccount(serviceAccountSource);
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: signJwt(serviceAccount),
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error_description || "Không lấy được token gateway.");
  }
  const token = String(body.access_token);
  accessTokenCache.set(serviceAccountSource, {
    token,
    expiresAt: Date.now() + Number(body.expires_in ?? 3600) * 1000,
  });
  return token;
}

function createConfig(rootDir) {
  loadEnvFile(join(rootDir, ".env"));
  loadEnvFile(join(rootDir, "Quanlyhoatdong", ".env"));
  loadEnvFile(join(rootDir, "Loginqldoanhoi", ".env"));

  return {
    identityApiKey: process.env.VITE_IDENTITY_FIREBASE_API_KEY,
    identityProjectId:
      process.env.IDENTITY_FIREBASE_PROJECT_ID ||
      process.env.VITE_IDENTITY_FIREBASE_PROJECT_ID ||
      "login-qldoanhoi",
    activityProjectId:
      process.env.ACTIVITY_FIREBASE_PROJECT_ID ||
      process.env.VITE_FIREBASE_PROJECT_ID ||
      "quanlyhoatdong-278e0",
    identityServiceAccountPath:
      process.env.IDENTITY_SERVICE_ACCOUNT_JSON ||
      process.env.IDENTITY_SERVICE_ACCOUNT_PATH ||
      join(rootDir, "keys", "login-qldoanhoi.json"),
    activityServiceAccountPath:
      process.env.ACTIVITY_SERVICE_ACCOUNT_JSON ||
      process.env.ACTIVITY_SERVICE_ACCOUNT_PATH ||
      join(rootDir, "keys", "quanlyhoatdong.json"),
  };
}

function firestoreBase(projectId) {
  return `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents`;
}

function encodePath(path) {
  return path
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
}

function toFirestoreValue(value) {
  if (value === undefined) return undefined;
  if (value === null) return { nullValue: null };
  if (typeof value === "boolean") return { booleanValue: value };
  if (typeof value === "number") {
    return Number.isInteger(value)
      ? { integerValue: String(value) }
      : { doubleValue: value };
  }
  if (typeof value === "string") return { stringValue: value };
  if (Array.isArray(value)) {
    return {
      arrayValue: {
        values: value.map(toFirestoreValue).filter(Boolean),
      },
    };
  }
  if (typeof value === "object") {
    const fields = {};
    for (const [key, nestedValue] of Object.entries(value)) {
      const converted = toFirestoreValue(nestedValue);
      if (converted) fields[key] = converted;
    }
    return { mapValue: { fields } };
  }
  return { stringValue: String(value) };
}

function toFirestoreFields(data) {
  const fields = {};
  for (const [key, value] of Object.entries(data ?? {})) {
    const converted = toFirestoreValue(value);
    if (converted) fields[key] = converted;
  }
  return fields;
}

function fromFirestoreValue(value) {
  if (!value || typeof value !== "object") return undefined;
  if ("nullValue" in value) return null;
  if ("booleanValue" in value) return value.booleanValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("timestampValue" in value) return value.timestampValue;
  if ("stringValue" in value) return value.stringValue;
  if ("arrayValue" in value) {
    return (value.arrayValue.values ?? []).map(fromFirestoreValue);
  }
  if ("mapValue" in value) {
    const result = {};
    for (const [key, nestedValue] of Object.entries(
      value.mapValue.fields ?? {},
    )) {
      result[key] = fromFirestoreValue(nestedValue);
    }
    return result;
  }
  return undefined;
}

function fromFirestoreDocument(document) {
  if (!document) return null;
  const id = String(document.name ?? "").split("/").pop();
  const data = {};
  for (const [key, value] of Object.entries(document.fields ?? {})) {
    data[key] = fromFirestoreValue(value);
  }
  return { id, ...data };
}

async function firestoreRequest(config, target, path, options = {}) {
  const projectId =
    target === "identity" ? config.identityProjectId : config.activityProjectId;
  const serviceAccountPath =
    target === "identity"
      ? config.identityServiceAccountPath
      : config.activityServiceAccountPath;
  const token = await getAccessToken(serviceAccountPath);
  const url = new URL(`${firestoreBase(projectId)}/${encodePath(path)}`);
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (Array.isArray(value)) {
      value.forEach((item) => url.searchParams.append(key, item));
    } else if (value !== undefined) {
      url.searchParams.set(key, String(value));
    }
  }

  const response = await fetch(url, {
    method: options.method ?? "GET",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = body?.error?.message || "Lỗi Firestore gateway.";
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return body;
}

async function getDoc(config, target, path) {
  try {
    return fromFirestoreDocument(await firestoreRequest(config, target, path));
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

async function listCollection(config, target, collectionPath) {
  const body = await firestoreRequest(config, target, collectionPath);
  return (body.documents ?? []).map(fromFirestoreDocument).filter(Boolean);
}

async function setDoc(config, target, path, data) {
  return firestoreRequest(config, target, path, {
    method: "PATCH",
    body: { fields: toFirestoreFields(data) },
  });
}

async function updateDoc(config, target, path, data) {
  const cleanData = Object.fromEntries(
    Object.entries(data ?? {}).filter(([, value]) => value !== undefined),
  );
  const keys = Object.keys(cleanData);
  if (!keys.length) return;
  return firestoreRequest(config, target, path, {
    method: "PATCH",
    query: { "updateMask.fieldPaths": keys },
    body: { fields: toFirestoreFields(cleanData) },
  });
}

async function addDoc(config, target, collectionPath, data) {
  return firestoreRequest(config, target, collectionPath, {
    method: "POST",
    body: { fields: toFirestoreFields(data) },
  });
}

async function deleteDoc(config, target, path) {
  return firestoreRequest(config, target, path, { method: "DELETE" });
}

function createSearchKeywords(values) {
  return values
    .flatMap((value) => String(value ?? "").toLowerCase().split(/\s+/))
    .map((value) => value.trim())
    .filter(Boolean);
}

function isSystemAdmin(profile) {
  return ["super_admin", "admin_doan_hoi"].includes(profile?.ma_vai_tro);
}

function hasPermission(ctx, permission) {
  return ctx.permissions.includes(permission);
}

function requirePermission(ctx, permission) {
  if (!hasPermission(ctx, permission)) {
    const error = new Error("Bạn không có quyền thực hiện thao tác này.");
    error.status = 403;
    throw error;
  }
}

function getDescendantUnitIds(units, rootUnitId) {
  if (!rootUnitId) return [];
  const childrenByParent = units.reduce((result, unit) => {
    const parentId = String(unit.ma_don_vi_cha || "");
    result[parentId] ??= [];
    result[parentId].push(unit);
    return result;
  }, {});

  const result = new Set([rootUnitId]);
  const queue = [rootUnitId];
  while (queue.length) {
    const parentId = queue.shift();
    for (const child of childrenByParent[parentId] ?? []) {
      if (result.has(child.ma_don_vi)) continue;
      result.add(child.ma_don_vi);
      queue.push(child.ma_don_vi);
    }
  }
  return Array.from(result);
}

function getAncestorUnitIds(units, unitId) {
  const byId = new Map(units.map((unit) => [unit.ma_don_vi, unit]));
  const result = [];
  const seen = new Set();
  let currentId = unitId;
  while (currentId && !seen.has(currentId)) {
    seen.add(currentId);
    result.push(currentId);
    currentId = String(byId.get(currentId)?.ma_don_vi_cha || "");
  }
  return result;
}

async function getAllUnits(config) {
  return listCollection(config, "identity", "don_vi").then((rows) =>
    rows.map(({ id, ...unit }) => ({ ma_don_vi: id, ...unit })),
  );
}

async function canAccessUnit(config, ctx, unitId) {
  if (!unitId) return false;
  if (isSystemAdmin(ctx.profile)) return true;
  const units = await getAllUnits(config);
  return getDescendantUnitIds(units, ctx.profile.ma_don_vi).includes(unitId);
}

async function getUnitPathIds(config, unitId) {
  const units = await getAllUnits(config);
  return getAncestorUnitIds(units, unitId);
}

async function assertActivityAccess(config, ctx, activity, permission) {
  requirePermission(ctx, permission);
  if (!(await canAccessUnit(config, ctx, activity.ma_don_vi))) {
    const error = new Error("Bạn không có quyền thao tác với đơn vị này.");
    error.status = 403;
    throw error;
  }
}

async function assertSchoolYearUnlocked(config, ctx, maNamHoc) {
  if (ctx.profile.ma_vai_tro === "super_admin" || !maNamHoc) return;
  const year = await getDoc(config, "activity", `nam_hoc/${maNamHoc}`);
  if (year?.trang_thai === "da_khoa") {
    const error = new Error("Năm học đã khóa, không thể thao tác hoạt động.");
    error.status = 403;
    throw error;
  }
}

async function addAuditLog(config, ctx, log) {
  await addDoc(config, "identity", "nhat_ky_he_thong", {
    ...log,
    nguoi_thuc_hien: ctx.profile.uid,
    ten_nguoi_thuc_hien: ctx.profile.ho_ten,
    thoi_gian: new Date().toISOString(),
    muc_do: log.muc_do ?? "thong_tin",
  }).catch(() => undefined);
}

async function verifyIdToken(config, idToken) {
  if (!config.identityApiKey) {
    throw new Error("Gateway thiếu VITE_IDENTITY_FIREBASE_API_KEY.");
  }
  const response = await fetch(
    `${IDENTITY_TOOLKIT_URL}?key=${encodeURIComponent(config.identityApiKey)}`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ idToken }),
    },
  );
  const body = await response.json().catch(() => ({}));
  if (!response.ok || !body.users?.[0]?.localId) {
    const error = new Error("Phiên đăng nhập không hợp lệ hoặc đã hết hạn.");
    error.status = 401;
    throw error;
  }
  return body.users[0].localId;
}

async function buildContext(config, request) {
  const authorization = request.headers.authorization ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    const error = new Error("Thiếu token đăng nhập.");
    error.status = 401;
    throw error;
  }

  const uid = await verifyIdToken(config, match[1]);
  const profile = await getDoc(config, "identity", `nguoi_dung/${uid}`);
  if (!profile) {
    const error = new Error("Không tìm thấy tài khoản người dùng.");
    error.status = 403;
    throw error;
  }
  if (profile.trang_thai && profile.trang_thai !== "dang_hoat_dong") {
    const error = new Error("Tài khoản không còn hoạt động.");
    error.status = 403;
    throw error;
  }

  const role = await getDoc(config, "identity", `vai_tro/${profile.ma_vai_tro}`);
  const permissions = Array.from(new Set(role?.danh_sach_quyen ?? []));
  const systems = Array.from(new Set(role?.danh_sach_he_thong ?? []));
  return { uid, profile: { uid, ...profile }, role, permissions, systems };
}

async function createActivity(config, ctx, rawData, status = "ban_nhap") {
  requirePermission(ctx, "them_hoat_dong");
  if (rawData.ma_don_vi && !(await canAccessUnit(config, ctx, rawData.ma_don_vi))) {
    const error = new Error("Bạn không có quyền tạo hoạt động cho đơn vị này.");
    error.status = 403;
    throw error;
  }
  await assertSchoolYearUnlocked(config, ctx, rawData.ma_nam_hoc);

  const [year, type, unit] = await Promise.all([
    getDoc(config, "activity", `nam_hoc/${rawData.ma_nam_hoc}`),
    getDoc(config, "activity", `loai_hoat_dong/${rawData.ma_loai}`),
    getDoc(config, "identity", `don_vi/${rawData.ma_don_vi}`),
  ]);
  if (!year) throw new Error("Năm học không tồn tại.");
  if (!type) throw new Error("Loại hoạt động không tồn tại.");
  if (!unit) throw new Error("Đơn vị không tồn tại.");

  const maHoatDong = rawData.ma_hoat_dong || `hd_${rawData.ma_nam_hoc}_${Date.now()}`;
  const now = new Date().toISOString();
  const data = {
    ...rawData,
    ma_hoat_dong: maHoatDong,
    ten_nam_hoc: year.ten_nam_hoc,
    ten_loai: type.ten_loai,
    mau_hien_thi: type.mau_hien_thi,
    ten_don_vi: unit.ten_don_vi,
    don_vi_path_ids: await getUnitPathIds(config, rawData.ma_don_vi),
    trang_thai: status,
    nguoi_tao: ctx.uid,
    ten_nguoi_tao: ctx.profile.ho_ten,
    so_luong_minh_chung: Number(rawData.so_luong_minh_chung ?? 0),
    da_luu_tru: Boolean(rawData.da_luu_tru ?? false),
    tu_khoa_tim_kiem:
      rawData.tu_khoa_tim_kiem ??
      createSearchKeywords([
        rawData.ten_hoat_dong,
        year.ten_nam_hoc,
        type.ten_loai,
        unit.ten_don_vi,
        rawData.dia_diem,
      ]),
    ngay_tao: now,
    ngay_cap_nhat: now,
    ...(status === "cho_duyet" ? { ngay_gui_duyet: now } : {}),
  };

  await setDoc(config, "activity", `hoat_dong/${maHoatDong}`, data);
  await addAuditLog(config, ctx, {
    hanh_dong: status === "cho_duyet" ? "them_va_gui_duyet_hoat_dong" : "them_hoat_dong",
    module: "hoat_dong",
    ma_doi_tuong: maHoatDong,
    noi_dung: `Thêm hoạt động ${rawData.ten_hoat_dong ?? maHoatDong}`,
  });
  return { id: maHoatDong };
}

async function updateActivity(config, ctx, maHoatDong, data) {
  const activity = await getDoc(config, "activity", `hoat_dong/${maHoatDong}`);
  if (!activity) throw new Error("Không tìm thấy hoạt động.");
  await assertActivityAccess(config, ctx, activity, "sua_hoat_dong");
  await assertSchoolYearUnlocked(config, ctx, activity.ma_nam_hoc);
  if (
    activity.trang_thai === "da_duyet" &&
    !isSystemAdmin(ctx.profile) &&
    !hasPermission(ctx, "duyet_hoat_dong")
  ) {
    const error = new Error("Không được sửa hoạt động đã duyệt.");
    error.status = 403;
    throw error;
  }

  const nextUnitId = String(data.ma_don_vi || activity.ma_don_vi || "");
  if (nextUnitId && !(await canAccessUnit(config, ctx, nextUnitId))) {
    const error = new Error("Bạn không có quyền chuyển hoạt động sang đơn vị này.");
    error.status = 403;
    throw error;
  }

  const [nextYear, nextType, nextUnit] = await Promise.all([
    data.ma_nam_hoc ? getDoc(config, "activity", `nam_hoc/${data.ma_nam_hoc}`) : Promise.resolve(null),
    data.ma_loai ? getDoc(config, "activity", `loai_hoat_dong/${data.ma_loai}`) : Promise.resolve(null),
    data.ma_don_vi ? getDoc(config, "identity", `don_vi/${data.ma_don_vi}`) : Promise.resolve(null),
  ]);

  await updateDoc(config, "activity", `hoat_dong/${maHoatDong}`, {
    ...data,
    ...(nextYear ? { ten_nam_hoc: nextYear.ten_nam_hoc } : {}),
    ...(nextType ? { ten_loai: nextType.ten_loai, mau_hien_thi: nextType.mau_hien_thi } : {}),
    ...(nextUnit ? { ten_don_vi: nextUnit.ten_don_vi } : {}),
    ...(nextUnitId ? { don_vi_path_ids: await getUnitPathIds(config, nextUnitId) } : {}),
    tu_khoa_tim_kiem: createSearchKeywords([
      data.ten_hoat_dong ?? activity.ten_hoat_dong,
      nextYear?.ten_nam_hoc ?? activity.ten_nam_hoc,
      nextType?.ten_loai ?? activity.ten_loai,
      nextUnit?.ten_don_vi ?? activity.ten_don_vi,
      data.dia_diem ?? activity.dia_diem,
    ]),
    ngay_cap_nhat: new Date().toISOString(),
  });
  await addAuditLog(config, ctx, {
    hanh_dong: "sua_hoat_dong",
    module: "hoat_dong",
    ma_doi_tuong: maHoatDong,
    noi_dung: `Cập nhật hoạt động ${activity.ten_hoat_dong}`,
  });
  return { id: maHoatDong };
}

async function deleteActivity(config, ctx, maHoatDong) {
  const activity = await getDoc(config, "activity", `hoat_dong/${maHoatDong}`);
  if (!activity) throw new Error("Không tìm thấy hoạt động.");
  await assertActivityAccess(config, ctx, activity, "xoa_hoat_dong");
  await assertSchoolYearUnlocked(config, ctx, activity.ma_nam_hoc);
  await deleteDoc(config, "activity", `hoat_dong/${maHoatDong}`);
  await addAuditLog(config, ctx, {
    hanh_dong: "xoa_hoat_dong",
    module: "hoat_dong",
    ma_doi_tuong: maHoatDong,
    noi_dung: `Xóa hoạt động ${activity.ten_hoat_dong}`,
    muc_do: "canh_bao",
  });
  return { id: maHoatDong };
}

async function setFeatured(config, ctx, maHoatDong, featured) {
  const activity = await getDoc(config, "activity", `hoat_dong/${maHoatDong}`);
  if (!activity) throw new Error("Không tìm thấy hoạt động.");
  await assertActivityAccess(config, ctx, activity, "sua_hoat_dong");
  if (featured && activity.trang_thai !== "da_duyet") {
    throw new Error("Chỉ hoạt động đã duyệt mới được hiển thị nổi bật.");
  }
  await updateDoc(config, "activity", `hoat_dong/${maHoatDong}`, {
    hien_thi_noi_bat: Boolean(featured),
    ngay_cap_nhat: new Date().toISOString(),
  });
  await addAuditLog(config, ctx, {
    hanh_dong: featured ? "bat_noi_bat_hoat_dong" : "tat_noi_bat_hoat_dong",
    module: "hoat_dong",
    ma_doi_tuong: maHoatDong,
    noi_dung: `${featured ? "Hiển thị nổi bật" : "Ẩn khỏi nổi bật"}: ${activity.ten_hoat_dong}`,
  });
  return { id: maHoatDong };
}

async function transitionActivity(config, ctx, maHoatDong, action, status, nhanXet = "") {
  const permissionByAction = {
    gui_duyet: "gui_duyet_hoat_dong",
    duyet: "duyet_hoat_dong",
    yeu_cau_bo_sung: "yeu_cau_bo_sung_hoat_dong",
    tu_choi: "tu_choi_hoat_dong",
  };
  const permission = permissionByAction[action];
  if (!permission) throw new Error("Thao tác duyệt không hợp lệ.");

  const activity = await getDoc(config, "activity", `hoat_dong/${maHoatDong}`);
  if (!activity) throw new Error("Không tìm thấy hoạt động.");
  await assertActivityAccess(config, ctx, activity, permission);
  await assertSchoolYearUnlocked(config, ctx, activity.ma_nam_hoc);

  const now = new Date().toISOString();
  await updateDoc(config, "activity", `hoat_dong/${maHoatDong}`, {
    trang_thai: status,
    ngay_cap_nhat: now,
    ...(action === "gui_duyet" ? { ngay_gui_duyet: now } : {}),
    ...(action === "duyet"
      ? { ngay_duyet: now, nguoi_duyet: ctx.uid, ten_nguoi_duyet: ctx.profile.ho_ten }
      : {}),
    ...(action === "yeu_cau_bo_sung" ? { ly_do_yeu_cau_bo_sung: nhanXet } : {}),
  });
  await addDoc(config, "activity", "duyet_hoat_dong", {
    ma_hoat_dong: maHoatDong,
    ten_hoat_dong: activity.ten_hoat_dong,
    hanh_dong: action,
    trang_thai_truoc: activity.trang_thai,
    trang_thai_sau: status,
    nhan_xet: nhanXet,
    nguoi_thuc_hien: ctx.uid,
    ten_nguoi_thuc_hien: ctx.profile.ho_ten,
    ngay_thuc_hien: now,
  });
  await addAuditLog(config, ctx, {
    hanh_dong: action,
    module: "hoat_dong",
    ma_doi_tuong: maHoatDong,
    noi_dung: `${action}: ${activity.ten_hoat_dong}`,
  });
  return { id: maHoatDong };
}

async function addEvidence(config, ctx, data) {
  requirePermission(ctx, "quan_ly_minh_chung");
  if (data.ma_don_vi && !(await canAccessUnit(config, ctx, String(data.ma_don_vi)))) {
    const error = new Error("Bạn không có quyền thêm minh chứng cho đơn vị này.");
    error.status = 403;
    throw error;
  }
  if (data.ma_hoat_dong) {
    const activity = await getDoc(config, "activity", `hoat_dong/${data.ma_hoat_dong}`);
    if (activity) await assertActivityAccess(config, ctx, activity, "quan_ly_minh_chung");
  }

  const now = new Date().toISOString();
  const response = await addDoc(config, "activity", "minh_chung", {
    ...data,
    ...(data.ma_don_vi
      ? { don_vi_path_ids: await getUnitPathIds(config, String(data.ma_don_vi)) }
      : {}),
    trang_thai: data.trang_thai ?? "dang_hoat_dong",
    ngay_tai_len: now,
  });
  const id = String(response.name ?? "").split("/").pop();
  if (id) {
    await updateDoc(config, "activity", `minh_chung/${id}`, { ma_minh_chung: id });
  }
  await addAuditLog(config, ctx, {
    hanh_dong: "them_minh_chung",
    module: "minh_chung",
    ma_doi_tuong: id,
    noi_dung: `Thêm minh chứng ${data.ten_minh_chung ?? id}`,
  });
  return { id };
}

async function updateEvidence(config, ctx, maMinhChung, data) {
  requirePermission(ctx, "quan_ly_minh_chung");
  const evidence = await getDoc(config, "activity", `minh_chung/${maMinhChung}`);
  if (!evidence) throw new Error("Không tìm thấy minh chứng.");
  const unitId = String(data.ma_don_vi || evidence.ma_don_vi || "");
  if (unitId && !(await canAccessUnit(config, ctx, unitId))) {
    const error = new Error("Bạn không có quyền sửa minh chứng của đơn vị này.");
    error.status = 403;
    throw error;
  }
  await updateDoc(config, "activity", `minh_chung/${maMinhChung}`, {
    ...data,
    ...(data.ma_don_vi ? { don_vi_path_ids: await getUnitPathIds(config, String(data.ma_don_vi)) } : {}),
  });
  await addAuditLog(config, ctx, {
    hanh_dong: "sua_minh_chung",
    module: "minh_chung",
    ma_doi_tuong: maMinhChung,
    noi_dung: `Cập nhật minh chứng ${evidence.ten_minh_chung ?? maMinhChung}`,
  });
  return { id: maMinhChung };
}

async function deleteEvidence(config, ctx, maMinhChung) {
  requirePermission(ctx, "quan_ly_minh_chung");
  const evidence = await getDoc(config, "activity", `minh_chung/${maMinhChung}`);
  if (!evidence) throw new Error("Không tìm thấy minh chứng.");
  if (evidence.ma_don_vi && !(await canAccessUnit(config, ctx, String(evidence.ma_don_vi)))) {
    const error = new Error("Bạn không có quyền xóa minh chứng của đơn vị này.");
    error.status = 403;
    throw error;
  }
  await deleteDoc(config, "activity", `minh_chung/${maMinhChung}`);
  await addAuditLog(config, ctx, {
    hanh_dong: "xoa_minh_chung",
    module: "minh_chung",
    ma_doi_tuong: maMinhChung,
    noi_dung: "Xóa minh chứng",
    muc_do: "canh_bao",
  });
  return { id: maMinhChung };
}

async function handleActivityAction(config, ctx, body) {
  const { action, payload = {} } = body;
  switch (action) {
    case "activities.create":
      return createActivity(config, ctx, payload.data, payload.status ?? "ban_nhap");
    case "activities.update":
      return updateActivity(config, ctx, payload.id, payload.data);
    case "activities.delete":
      return deleteActivity(config, ctx, payload.id);
    case "activities.featured":
      return setFeatured(config, ctx, payload.id, payload.featured);
    case "activities.transition":
      return transitionActivity(
        config,
        ctx,
        payload.id,
        payload.action,
        payload.status,
        payload.comment ?? "",
      );
    default: {
      const error = new Error("Gateway chưa hỗ trợ thao tác này.");
      error.status = 400;
      throw error;
    }
  }
}

async function handleEvidenceAction(config, ctx, body) {
  const { action, payload = {} } = body;
  switch (action) {
    case "evidences.create":
      return addEvidence(config, ctx, payload.data);
    case "evidences.update":
      return updateEvidence(config, ctx, payload.id, payload.data);
    case "evidences.delete":
      return deleteEvidence(config, ctx, payload.id);
    default: {
      const error = new Error("Gateway chưa hỗ trợ thao tác này.");
      error.status = 400;
      throw error;
    }
  }
}

async function readJsonBody(request) {
  if (request.body !== undefined) {
    if (typeof request.body === "string") return JSON.parse(request.body || "{}");
    return request.body ?? {};
  }

  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(response, status, data) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
  });
  response.end(JSON.stringify(data));
}

export function createApiHandler(rootDir) {
  const config = createConfig(rootDir);

  return async function handleApi(request, response, url) {
    if (!url.pathname.startsWith("/api/")) return false;

    try {
      if (request.method === "OPTIONS") {
        response.writeHead(204, {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "POST, OPTIONS",
          "access-control-allow-headers": "content-type, authorization",
        });
        response.end();
        return true;
      }

      if (request.method !== "POST") {
        sendJson(response, 405, { ok: false, message: "Method not allowed" });
        return true;
      }

      const ctx = await buildContext(config, request);
      const body = await readJsonBody(request);

      if (url.pathname === "/api/activity") {
        const result = await handleActivityAction(config, ctx, body);
        sendJson(response, 200, { ok: true, data: result });
        return true;
      }

      if (url.pathname === "/api/evidence") {
        const result = await handleEvidenceAction(config, ctx, body);
        sendJson(response, 200, { ok: true, data: result });
        return true;
      }

      if (url.pathname === "/api/authz/profile") {
        sendJson(response, 200, {
          ok: true,
          data: {
            profile: ctx.profile,
            permissions: ctx.permissions,
            systems: ctx.systems,
          },
        });
        return true;
      }

      if (url.pathname === "/api/authz/activity-token") {
        const serviceAccount = loadServiceAccount(
          config.activityServiceAccountPath,
        );
        const token = signFirebaseCustomToken(serviceAccount, ctx.uid, {
          role: ctx.profile.ma_vai_tro,
          ma_vai_tro: ctx.profile.ma_vai_tro,
          ma_don_vi: ctx.profile.ma_don_vi ?? "",
          trang_thai: ctx.profile.trang_thai ?? "",
          permissions: ctx.permissions,
          systems: ctx.systems,
        });
        sendJson(response, 200, { ok: true, data: { token } });
        return true;
      }

      sendJson(response, 404, { ok: false, message: "API not found" });
      return true;
    } catch (error) {
      const status = Number(error.status || 500);
      sendJson(response, status, {
        ok: false,
        message:
          error instanceof Error ? error.message : "Internal gateway error",
      });
      return true;
    }
  };
}
