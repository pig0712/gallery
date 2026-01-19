(() => {
  "use strict";

  // =========================================================
  // Storage + Crypto
  // =========================================================
  const STORAGE_KEY = "OFFLINE_GALLERY_STATE_V2";
  const REMEMBER_KEY = "OFFLINE_GALLERY_REMEMBER_USERID_V1";

  const PBKDF2_ITERS = 120_000;
  const SALT_BYTES = 16;

  function $(sel) { return document.querySelector(sel); }
  function $$(sel) { return Array.from(document.querySelectorAll(sel)); }
  function nowISO() { return new Date().toISOString(); }

  function safeId(prefix = "") {
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    const b64 = btoa(String.fromCharCode(...bytes))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    return prefix + b64;
  }

  function bytesToB64(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function deriveHashB64(password, saltBytes) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: PBKDF2_ITERS,
        hash: "SHA-256",
      },
      keyMaterial,
      256
    );
    const hashBytes = new Uint8Array(bits);
    return bytesToB64(hashBytes);
  }

  function isValidUsername(u) {
    if (!u) return false;
    if (u.length < 2 || u.length > 20) return false;
    if (/\s/.test(u)) return false;
    return true;
  }

  function clampInt(n, min, max) {
    const x = Number(n);
    if (!Number.isFinite(x)) return min;
    return Math.max(min, Math.min(max, Math.trunc(x)));
  }

  function rgbToHex(r, g, b) {
    const to2 = (x) => x.toString(16).padStart(2, "0");
    return ("#" + to2(r) + to2(g) + to2(b)).toUpperCase();
  }

  function hexToRgb(hex) {
    const h = String(hex || "").trim();
    const m = /^#?([0-9a-fA-F]{6})$/.exec(h);
    if (!m) return { r: 110, g: 231, b: 255 };
    const v = m[1];
    return {
      r: parseInt(v.slice(0, 2), 16),
      g: parseInt(v.slice(2, 4), 16),
      b: parseInt(v.slice(4, 6), 16),
    };
  }

  function normalizeHex(hex) {
    const m = /^#?([0-9a-fA-F]{6})$/.exec(String(hex || "").trim());
    if (!m) return "#6EE7FF";
    return ("#" + m[1]).toUpperCase();
  }

  // =========================================================
  // State
  // =========================================================
  const state = loadState();

  const viewState = {
    userId: null,
    activeGalleryId: null,
    activeGalleryOwnerId: null, // gallery owner
    showTrash: false,
    query: "",
    viewMode: "grid",
  };

  function loadState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) {
        return {
          version: 2,
          users: {},         // userId -> { userId, username, saltB64, hashB64, createdAt, role }
          usernameIndex: {}, // username -> userId
          userData: {},      // userId -> { settings, galleries, posts, comments, media }
        };
      }
      const obj = JSON.parse(raw);
      obj.users ||= {};
      obj.usernameIndex ||= {};
      obj.userData ||= {};
      return obj;
    } catch (e) {
      console.error("Failed to load state:", e);
      return {
        version: 2,
        users: {},
        usernameIndex: {},
        userData: {},
      };
    }
  }

  function saveState() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }

  function ensureUserData(userId) {
    state.userData[userId] ||= {
      settings: { theme: "dark", accent: "#6EE7FF", viewMode: "grid" },
      galleries: {}, // gid -> gallery (owned by this user)
      posts: {},     // pid -> post (authored by this user; can belong to other user's gallery)
      comments: {},  // cid -> comment (authored by this user)
      media: {},     // reserved
    };
    const ud = state.userData[userId];
    ud.settings ||= { theme: "dark", accent: "#6EE7FF", viewMode: "grid" };
    ud.settings.theme ||= "dark";
    ud.settings.accent ||= "#6EE7FF";
    ud.settings.viewMode ||= "grid";
    ud.galleries ||= {};
    ud.posts ||= {};
    ud.comments ||= {};
    ud.media ||= {};
    return ud;
  }

  function isAdmin() {
    return state.users?.[viewState.userId]?.role === "admin";
  }

  function canManage(userId) {
    return isAdmin() || userId === viewState.userId;
  }

  // =========================================================
  // Bootstrap: remove demo, ensure admin
  // =========================================================
  (async function ensureAdminAndRemoveDemo() {
    try {
      // remove "demo" if exists
      const demoId = state.usernameIndex?.["demo"];
      if (demoId) {
        delete state.usernameIndex["demo"];
        delete state.users[demoId];
        delete state.userData[demoId];
        saveState();
      }

      const ADMIN_NAME = "admin";
      const ADMIN_PW = "qwer0987@";

      const adminId = state.usernameIndex?.[ADMIN_NAME];
      if (adminId && state.users?.[adminId]) {
        state.users[adminId].role = "admin";
        ensureUserData(adminId);
        saveState();
        return;
      }

      const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
      const hashB64 = await deriveHashB64(ADMIN_PW, salt);

      const userId = safeId("u_");
      state.users[userId] = {
        userId,
        username: ADMIN_NAME,
        saltB64: bytesToB64(salt),
        hashB64,
        createdAt: nowISO(),
        role: "admin",
      };
      state.usernameIndex[ADMIN_NAME] = userId;
      ensureUserData(userId);

      saveState();
    } catch (e) {
      console.error("[AdminBootstrap] failed:", e);
    }
  })();

  // =========================================================
  // Helpers: DOM
  // =========================================================
  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function el(tag, props = {}, children = []) {
    const e = document.createElement(tag);
    if (props.class) e.className = props.class;
    if (props.text != null) e.textContent = props.text;
    if (props.html != null) e.innerHTML = props.html;
    if (props.dataset) {
      for (const [k, v] of Object.entries(props.dataset)) e.dataset[k] = v;
    }
    if (props.attrs) {
      for (const [k, v] of Object.entries(props.attrs)) e.setAttribute(k, v);
    }
    for (const c of children) e.appendChild(c);
    return e;
  }

  function btn(text, cls, onClick) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = cls || "btnGhost";
    b.textContent = text;
    b.addEventListener("click", onClick);
    return b;
  }

  // =========================================================
  // Toast
  // =========================================================
  function toast({ title, message, timeoutMs = 2200 }) {
    const host = $("#toastHost");
    const t = document.createElement("div");
    t.className = "toast";
    t.innerHTML = `
      <div class="toastTitle">${escapeHtml(title || "")}</div>
      <div class="toastMsg">${escapeHtml(message || "")}</div>
    `;
    host.appendChild(t);
    setTimeout(() => {
      t.style.opacity = "0";
      t.style.transform = "translateY(6px)";
      setTimeout(() => t.remove(), 180);
    }, timeoutMs);
  }

  // =========================================================
  // Theme + Accent
  // =========================================================
  function applyTheme(theme) {
    const t = theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", t);

    $("#btnThemeDark")?.classList.toggle("isActive", t === "dark");
    $("#btnThemeLight")?.classList.toggle("isActive", t === "light");
    $("#btnThemeDark")?.setAttribute("aria-checked", String(t === "dark"));
    $("#btnThemeLight")?.setAttribute("aria-checked", String(t === "light"));
  }

  function applyAccent(hex) {
    const h = normalizeHex(hex);
    document.documentElement.style.setProperty("--accent", h);

    const pv = $("#accentPreview");
    const tx = $("#accentHexText");
    if (pv) pv.style.background = h;
    if (tx) tx.textContent = h;
  }

  function setRgbUi(r, g, b) {
    const ids = [
      ["rgbR", "rgbRNum", r],
      ["rgbG", "rgbGNum", g],
      ["rgbB", "rgbBNum", b],
    ];
    for (const [sliderId, numId, v] of ids) {
      const slider = $("#" + sliderId);
      const num = $("#" + numId);
      if (slider) slider.value = String(v);
      if (num) num.value = String(v);
    }
  }

  function getRgbUi() {
    const r = clampInt($("#rgbR")?.value ?? 110, 0, 255);
    const g = clampInt($("#rgbG")?.value ?? 231, 0, 255);
    const b = clampInt($("#rgbB")?.value ?? 255, 0, 255);
    return { r, g, b };
  }

  function updateAccentPreviewFromRgb() {
    const { r, g, b } = getRgbUi();
    const hex = rgbToHex(r, g, b);
    const pv = $("#accentPreview");
    const tx = $("#accentHexText");
    if (pv) pv.style.background = hex;
    if (tx) tx.textContent = hex;
    return hex;
  }

  function syncRgbUiFromAccent(hex) {
    const { r, g, b } = hexToRgb(hex);
    setRgbUi(r, g, b);
    updateAccentPreviewFromRgb();
  }

  // =========================================================
  // User menu backdrop
  // =========================================================
  function openUserMenu() {
    $("#userMenuPanel").classList.remove("isHidden");
    $("#menuBackdrop").classList.remove("isHidden");
    $("#btnUserMenu").setAttribute("aria-expanded", "true");

    const ud = ensureUserData(viewState.userId);
    applyTheme(ud.settings.theme || "dark");
    applyAccent(ud.settings.accent || "#6EE7FF");
    syncRgbUiFromAccent(ud.settings.accent || "#6EE7FF");

    $("#menuUserMeta").textContent = isAdmin()
      ? "관리자: 전체 갤러리/게시물/댓글 관리"
      : "전체 열람 가능 · 수정/삭제는 본인 작성분만";
  }

  function closeUserMenu() {
    $("#userMenuPanel").classList.add("isHidden");
    $("#menuBackdrop").classList.add("isHidden");
    $("#btnUserMenu").setAttribute("aria-expanded", "false");
  }

  // =========================================================
  // Modal
  // =========================================================
  function openModal({ title, bodyEl, footerEls = [] }) {
    $("#modalTitle").textContent = title || "";
    const body = $("#modalBody");
    const footer = $("#modalFooter");
    body.innerHTML = "";
    footer.innerHTML = "";

    if (bodyEl) body.appendChild(bodyEl);
    for (const e of footerEls) footer.appendChild(e);

    $("#modalBackdrop").classList.remove("isHidden");
    $("#modal").classList.remove("isHidden");
  }

  function closeModal() {
    $("#modalBackdrop").classList.add("isHidden");
    $("#modal").classList.add("isHidden");
    $("#modalBody").innerHTML = "";
    $("#modalFooter").innerHTML = "";
  }

  function confirmDanger(title, message, onConfirm) {
    const body = el("div", {}, [
      el("div", { class: "dangerText", text: title }),
      el("div", { class: "muted", text: message }),
    ]);
    openModal({
      title: "확인",
      bodyEl: body,
      footerEls: [
        btn("취소", "btnGhost", () => closeModal()),
        btn("확인", "btnGhost danger", () => { closeModal(); onConfirm?.(); }),
      ],
    });
  }

  // =========================================================
  // Data resolution (cross-user scan)
  // =========================================================
  function getUserName(userId) {
    return state.users?.[userId]?.username || "unknown";
  }

  function resolveGalleryCtx(gid, ownerHint) {
    if (!gid) return null;

    // try hint first
    if (ownerHint) {
      const ud = ensureUserData(ownerHint);
      const g = ud.galleries?.[gid];
      if (g) return { ownerId: ownerHint, ud, g };
    }

    // scan all
    for (const ownerId of Object.keys(state.userData || {})) {
      const ud = ensureUserData(ownerId);
      const g = ud.galleries?.[gid];
      if (g) return { ownerId, ud, g };
    }
    return null;
  }

  function resolvePostCtx(pid, authorHint) {
    if (!pid) return null;

    if (authorHint) {
      const ud = ensureUserData(authorHint);
      const p = ud.posts?.[pid];
      if (p) return { ownerId: authorHint, ud, p };
    }
    for (const ownerId of Object.keys(state.userData || {})) {
      const ud = ensureUserData(ownerId);
      const p = ud.posts?.[pid];
      if (p) return { ownerId, ud, p };
    }
    return null;
  }

  function listAllGalleryEntries({ includeDeleted = false } = {}) {
    const out = [];
    const owners = Object.keys(state.userData || {});
    for (const ownerId of owners) {
      const ud = ensureUserData(ownerId);
      for (const g of Object.values(ud.galleries || {})) {
        if (!includeDeleted && g.deletedAt) continue;
        out.push({ ownerId, ownerName: getUserName(ownerId), ud, g });
      }
    }
    return out;
  }

  function listPostsInGallery(galleryOwnerId, galleryId, { includeDeleted = false } = {}) {
    const out = [];
    const owners = Object.keys(state.userData || {});
    for (const authorId of owners) {
      const ud = ensureUserData(authorId);
      for (const p of Object.values(ud.posts || {})) {
        // backward compat: if p.galleryOwnerId missing, assume author == gallery owner
        const go = p.galleryOwnerId || authorId;
        if (go !== galleryOwnerId) continue;
        if (p.galleryId !== galleryId) continue;
        if (!includeDeleted && p.deletedAt) continue;
        out.push({ ownerId: authorId, ownerName: getUserName(authorId), ud, p });
      }
    }
    return out;
  }

  function listCommentsForPost(postId, { includeDeleted = false } = {}) {
    const out = [];
    const owners = Object.keys(state.userData || {});
    for (const authorId of owners) {
      const ud = ensureUserData(authorId);
      for (const c of Object.values(ud.comments || {})) {
        if (c.postId !== postId) continue;
        if (!includeDeleted && c.deletedAt) continue;
        out.push({ ownerId: authorId, ownerName: getUserName(authorId), ud, c });
      }
    }
    out.sort((a, b) => String(a.c.createdAt || "").localeCompare(String(b.c.createdAt || "")));
    return out;
  }

  function computeGalleryMeta(galleryOwnerId, galleryId) {
    const posts = listPostsInGallery(galleryOwnerId, galleryId, { includeDeleted: true });
    const alive = posts.filter(x => !x.p.deletedAt);
    const trashed = posts.filter(x => !!x.p.deletedAt);
    const latest = alive.reduce((acc, x) => {
      const t = x.p.updatedAt || x.p.createdAt || "";
      return acc > t ? acc : t;
    }, "");
    return {
      postCount: alive.length,
      trashedCount: trashed.length,
      latestAt: latest || null,
    };
  }

  // =========================================================
  // CRUD: Gallery (owned by creator only)
  // =========================================================
  function createGallery(ownerId, data) {
    if (!canManage(ownerId)) {
      toast({ title: "권한 없음", message: "갤러리를 생성할 수 없습니다." });
      return null;
    }
    const ud = ensureUserData(ownerId);
    const gid = safeId("g_");
    const g = {
      id: gid,
      title: String(data.title || "새 갤러리").trim(),
      desc: String(data.desc || "").trim(),
      icon: String(data.icon || "🖼️"),
      color: normalizeHex(data.color || "#6EE7FF"),
      pinned: !!data.pinned,
      createdAt: nowISO(),
      updatedAt: nowISO(),
      deletedAt: null,
    };
    ud.galleries[gid] = g;
    saveState();
    return g;
  }

  function updateGallery(ownerId, gid, patch) {
    if (!canManage(ownerId)) {
      toast({ title: "권한 없음", message: "이 갤러리를 수정할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(ownerId);
    const g = ud.galleries?.[gid];
    if (!g || g.deletedAt) return false;

    g.title = String(patch.title ?? g.title).trim();
    g.desc = String(patch.desc ?? g.desc).trim();
    g.icon = String(patch.icon ?? g.icon);
    g.color = normalizeHex(patch.color ?? g.color);
    g.pinned = patch.pinned != null ? !!patch.pinned : g.pinned;
    g.updatedAt = nowISO();
    saveState();
    return true;
  }

  // deleting a gallery soft-deletes ALL posts in that gallery (from any author)
  function deleteGallerySoft(ownerId, gid) {
    if (!canManage(ownerId)) {
      toast({ title: "권한 없음", message: "이 갤러리를 삭제할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(ownerId);
    const g = ud.galleries?.[gid];
    if (!g || g.deletedAt) return false;

    g.deletedAt = nowISO();
    g.updatedAt = nowISO();

    const posts = listPostsInGallery(ownerId, gid, { includeDeleted: true });
    for (const { ownerId: authorId, ud: aud, p } of posts) {
      if (!p.deletedAt) {
        p.deletedAt = nowISO();
        p.updatedAt = nowISO();
        p.deletedByGallery = true;
      }
    }

    saveState();
    return true;
  }

  function restoreGallery(ownerId, gid) {
    if (!canManage(ownerId)) {
      toast({ title: "권한 없음", message: "복원할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(ownerId);
    const g = ud.galleries?.[gid];
    if (!g || !g.deletedAt) return false;

    g.deletedAt = null;
    g.updatedAt = nowISO();

    // restore posts that were deleted due to gallery deletion
    const posts = listPostsInGallery(ownerId, gid, { includeDeleted: true });
    for (const { ud: aud, p } of posts) {
      if (p.deletedAt && p.deletedByGallery) {
        p.deletedAt = null;
        p.deletedByGallery = false;
        p.updatedAt = nowISO();
      }
    }

    saveState();
    return true;
  }

  function purgeGallery(ownerId, gid) {
    if (!canManage(ownerId)) {
      toast({ title: "권한 없음", message: "영구 삭제할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(ownerId);
    const g = ud.galleries?.[gid];
    if (!g) return false;

    // purge posts in that gallery (across all authors) + their comments
    const posts = listPostsInGallery(ownerId, gid, { includeDeleted: true });
    const postIds = new Set(posts.map(x => x.p.id));

    // remove comments across all authors pointing to those posts
    for (const commenterId of Object.keys(state.userData || {})) {
      const cud = ensureUserData(commenterId);
      for (const [cid, c] of Object.entries(cud.comments || {})) {
        if (postIds.has(c.postId)) delete cud.comments[cid];
      }
    }

    // remove posts across all authors
    for (const { ownerId: authorId, ud: aud, p } of posts) {
      delete aud.posts[p.id];
    }

    delete ud.galleries[gid];
    saveState();
    return true;
  }

  // =========================================================
  // CRUD: Post (authored by current user; can target any gallery)
  // =========================================================
  function createPost(authorId, data) {
    if (!canManage(authorId)) {
      toast({ title: "권한 없음", message: "게시물을 작성할 수 없습니다." });
      return null;
    }

    // verify target gallery exists
    const gctx = resolveGalleryCtx(data.galleryId, data.galleryOwnerId);
    if (!gctx || !gctx.g || gctx.g.deletedAt) {
      toast({ title: "오류", message: "유효한 갤러리를 선택하세요." });
      return null;
    }

    const ud = ensureUserData(authorId);
    const pid = safeId("p_");
    const p = {
      id: pid,
      galleryOwnerId: gctx.ownerId,
      galleryId: gctx.g.id,
      title: String(data.title || "새 게시물").trim(),
      content: String(data.content || "").trim(),
      attachments: [],
      createdAt: nowISO(),
      updatedAt: nowISO(),
      deletedAt: null,
      deletedByGallery: false,
    };
    ud.posts[pid] = p;
    saveState();
    return p;
  }

  function updatePost(authorId, pid, patch) {
    if (!canManage(authorId)) {
      toast({ title: "권한 없음", message: "이 게시물을 수정할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(authorId);
    const p = ud.posts?.[pid];
    if (!p || p.deletedAt) return false;

    p.title = String(patch.title ?? p.title).trim();
    p.content = String(patch.content ?? p.content).trim();
    p.updatedAt = nowISO();
    saveState();
    return true;
  }

  function deletePostSoft(authorId, pid) {
    if (!canManage(authorId)) {
      toast({ title: "권한 없음", message: "이 게시물을 삭제할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(authorId);
    const p = ud.posts?.[pid];
    if (!p || p.deletedAt) return false;

    p.deletedAt = nowISO();
    p.deletedByGallery = false;
    p.updatedAt = nowISO();
    saveState();
    return true;
  }

  function restorePost(authorId, pid) {
    if (!canManage(authorId)) {
      toast({ title: "권한 없음", message: "복원할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(authorId);
    const p = ud.posts?.[pid];
    if (!p || !p.deletedAt) return false;

    // ensure gallery exists and not deleted
    const gctx = resolveGalleryCtx(p.galleryId, p.galleryOwnerId);
    if (!gctx || !gctx.g || gctx.g.deletedAt) {
      toast({ title: "복원 불가", message: "갤러리가 삭제된 상태입니다. 먼저 갤러리를 복원하세요." });
      return false;
    }

    p.deletedAt = null;
    p.deletedByGallery = false;
    p.updatedAt = nowISO();
    saveState();
    return true;
  }

  function purgePost(authorId, pid) {
    if (!canManage(authorId)) {
      toast({ title: "권한 없음", message: "영구 삭제할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(authorId);
    const p = ud.posts?.[pid];
    if (!p) return false;

    // purge comments across all users
    for (const commenterId of Object.keys(state.userData || {})) {
      const cud = ensureUserData(commenterId);
      for (const [cid, c] of Object.entries(cud.comments || {})) {
        if (c.postId === pid) delete cud.comments[cid];
      }
    }

    delete ud.posts[pid];
    saveState();
    return true;
  }

  // =========================================================
  // CRUD: Comment (authored by current user)
  // =========================================================
  function createComment(authorId, postId, text) {
    if (!canManage(authorId)) {
      toast({ title: "권한 없음", message: "댓글을 작성할 수 없습니다." });
      return null;
    }
    const postCtx = resolvePostCtx(postId, null);
    if (!postCtx || !postCtx.p || postCtx.p.deletedAt) {
      toast({ title: "오류", message: "유효한 게시물이 아닙니다." });
      return null;
    }
    const ud = ensureUserData(authorId);
    const cid = safeId("c_");
    const c = {
      id: cid,
      postId,
      text: String(text || "").trim(),
      createdAt: nowISO(),
      updatedAt: nowISO(),
      deletedAt: null,
    };
    ud.comments[cid] = c;
    saveState();
    return c;
  }

  function updateComment(authorId, cid, patch) {
    if (!canManage(authorId)) {
      toast({ title: "권한 없음", message: "댓글을 수정할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(authorId);
    const c = ud.comments?.[cid];
    if (!c || c.deletedAt) return false;

    c.text = String(patch.text ?? c.text).trim();
    c.updatedAt = nowISO();
    saveState();
    return true;
  }

  function deleteCommentSoft(authorId, cid) {
    if (!canManage(authorId)) {
      toast({ title: "권한 없음", message: "댓글을 삭제할 수 없습니다." });
      return false;
    }
    const ud = ensureUserData(authorId);
    const c = ud.comments?.[cid];
    if (!c || c.deletedAt) return false;

    c.deletedAt = nowISO();
    c.updatedAt = nowISO();
    saveState();
    return true;
  }

  // =========================================================
  // Rendering
  // =========================================================
  function iconText(icon) {
    return String(icon || "🖼️");
  }

  function renderAll() {
    renderTop();
    renderSidebarList();
    renderContextBar();
    renderContent();
  }

  function renderTop() {
    const user = state.users?.[viewState.userId];
    const ud = ensureUserData(viewState.userId);

    $("#chipUser").textContent = user ? user.username : "—";
    $("#chipRole").classList.toggle("isHidden", !isAdmin());
    $("#topSubtitle").textContent = isAdmin()
      ? "ADMIN: 전체 수정/삭제 가능"
      : "전체 열람 가능 · 수정/삭제는 본인 작성분만";

    applyTheme(ud.settings.theme || "dark");
    applyAccent(ud.settings.accent || "#6EE7FF");
    viewState.viewMode = ud.settings.viewMode || "grid";
    $("#btnViewGrid").classList.toggle("isActive", viewState.viewMode === "grid");
    $("#btnViewList").classList.toggle("isActive", viewState.viewMode === "list");
  }

  function renderSidebarList() {
    const list = $("#galleryList");
    list.innerHTML = "";

    const q = viewState.query.toLowerCase().trim();
    const includeDeleted = !!viewState.showTrash;

    const entries = listAllGalleryEntries({ includeDeleted });

    const filtered = entries.filter(({ g, ownerName }) => {
      const hay = `${g.title || ""}\n${g.desc || ""}\n${ownerName || ""}`.toLowerCase();
      return !q || hay.includes(q);
    });

    filtered.sort((a, b) => {
      if (!includeDeleted && !!a.g.pinned !== !!b.g.pinned) return a.g.pinned ? -1 : 1;
      return String(b.g.updatedAt || "").localeCompare(String(a.g.updatedAt || ""));
    });

    for (const { ownerId, ownerName, g } of filtered) {
      const isActive =
        !viewState.showTrash &&
        viewState.activeGalleryId === g.id &&
        (viewState.activeGalleryOwnerId || ownerId) === ownerId;

      const item = el("div", { class: "galleryItem" + (isActive ? " isActive" : "") });

      const icon = el("div", { class: "gIcon", attrs: { "aria-hidden": "true" } });
      icon.style.background = `color-mix(in srgb, ${g.color || "#6EE7FF"} 25%, rgba(255,255,255,.03))`;
      icon.style.borderColor = `color-mix(in srgb, ${g.color || "#6EE7FF"} 40%, var(--stroke))`;
      icon.appendChild(el("span", { class: "muted small", text: iconText(g.icon) }));

      const meta = computeGalleryMeta(ownerId, g.id);

      const metaParts = [
        `${meta.postCount}개`,
        includeDeleted ? "삭제됨" : (g.pinned ? "고정" : null),
        `소유자: ${ownerName}`,
      ].filter(Boolean);

      const text = el("div", { class: "gText" }, [
        el("div", { class: "gName", text: g.title || "제목 없음" }),
        el("div", { class: "gMeta" }, metaParts.map(s => el("span", { text: s })))
      ]);

      item.append(icon, text);

      item.addEventListener("click", () => {
        viewState.activeGalleryId = g.id;
        viewState.activeGalleryOwnerId = ownerId;
        renderAll();
      });

      list.appendChild(item);
    }

    $("#btnAllGalleries").classList.toggle("isActive", !viewState.showTrash);
    $("#btnTrash").classList.toggle("isActive", viewState.showTrash);
  }

  function renderContextBar() {
    const titleEl = $("#contextTitle");
    const metaEl = $("#contextMeta");
    const btnEdit = $("#btnEditGallery");
    const btnDel = $("#btnDeleteGallery");

    if (viewState.showTrash) {
      titleEl.textContent = "휴지통";
      metaEl.textContent = "삭제된 갤러리/게시물을 복원하거나 영구 삭제할 수 있습니다.";
      btnEdit.classList.add("isHidden");
      btnDel.classList.add("isHidden");
      return;
    }

    if (!viewState.activeGalleryId) {
      titleEl.textContent = "전체 갤러리";
      metaEl.textContent = "갤러리를 선택하거나 새로 생성하세요.";
      btnEdit.classList.add("isHidden");
      btnDel.classList.add("isHidden");
      return;
    }

    const ctx = resolveGalleryCtx(viewState.activeGalleryId, viewState.activeGalleryOwnerId);
    if (!ctx || !ctx.g || ctx.g.deletedAt) {
      viewState.activeGalleryId = null;
      viewState.activeGalleryOwnerId = null;
      renderAll();
      return;
    }

    const { ownerId, g } = ctx;
    const ownerName = getUserName(ownerId);
    const meta = computeGalleryMeta(ownerId, g.id);

    titleEl.textContent = `${g.icon || "🖼️"} ${g.title}`;
    const parts = [
      `${meta.postCount}개 게시물`,
      meta.latestAt ? `최근: ${meta.latestAt.slice(0, 10)}` : null,
      `소유자: ${ownerName}`,
    ].filter(Boolean);

    metaEl.textContent = parts.join(" · ");

    // Only gallery owner (or admin) can edit/delete gallery
    const manageable = canManage(ownerId);
    btnEdit.classList.toggle("isHidden", !manageable);
    btnDel.classList.toggle("isHidden", !manageable);
  }

  function renderContent() {
    const body = $("#contentBody");
    body.innerHTML = "";

    const q = viewState.query.toLowerCase().trim();

    if (viewState.showTrash) {
      body.appendChild(renderTrashView(q));
      return;
    }

    if (!viewState.activeGalleryId) {
      body.appendChild(renderGalleriesView(q));
      return;
    }

    const ctx = resolveGalleryCtx(viewState.activeGalleryId, viewState.activeGalleryOwnerId);
    if (!ctx || !ctx.g || ctx.g.deletedAt) {
      viewState.activeGalleryId = null;
      viewState.activeGalleryOwnerId = null;
      renderAll();
      return;
    }

    body.appendChild(renderPostsView(ctx.ownerId, ctx.g.id, q));
  }

  function renderGalleriesView(q) {
    const entries = listAllGalleryEntries({ includeDeleted: false });

    const filtered = entries.filter(({ g, ownerName }) => {
      const hay = `${g.title || ""}\n${g.desc || ""}\n${ownerName || ""}`.toLowerCase();
      return !q || hay.includes(q);
    });

    filtered.sort((a, b) => {
      if (!!a.g.pinned !== !!b.g.pinned) return a.g.pinned ? -1 : 1;
      return String(b.g.updatedAt || "").localeCompare(String(a.g.updatedAt || ""));
    });

    if (filtered.length === 0) {
      return el("div", { class: "muted", text: "표시할 갤러리가 없습니다." });
    }

    if (viewState.viewMode === "list") {
      const list = el("div", { class: "list" });
      for (const { ownerId, ownerName, g } of filtered) {
        const meta = computeGalleryMeta(ownerId, g.id);

        const row = el("div", { class: "listRow" }, [
          el("div", { class: "listLeft" }, [
            el("div", { class: "listTitle", text: `${g.icon || "🖼️"} ${g.title}` }),
            el("div", { class: "listSub" }, [
              el("span", { text: `${meta.postCount}개` }),
              el("span", { class: "badge", text: `소유자: ${ownerName}` }),
              g.pinned ? el("span", { class: "badge accent", text: "고정" }) : el("span", { text: "" }),
            ].filter(x => x.textContent !== "")),
          ]),
          el("div", { class: "listRight" }, [
            el("span", { class: "badge", text: g.color }),
          ]),
        ]);

        row.addEventListener("click", () => {
          viewState.activeGalleryId = g.id;
          viewState.activeGalleryOwnerId = ownerId;
          renderAll();
        });

        list.appendChild(row);
      }
      return list;
    }

    const grid = el("div", { class: "grid" });
    for (const { ownerId, ownerName, g } of filtered) {
      const meta = computeGalleryMeta(ownerId, g.id);

      const card = el("div", { class: "card" }, [
        el("div", { class: "cardTitle", text: `${g.icon || "🖼️"} ${g.title}` }),
        el("div", { class: "cardMeta" }, [
          el("span", { class: "badge", text: `${meta.postCount}개` }),
          el("span", { class: "badge", text: `소유자: ${ownerName}` }),
          g.pinned ? el("span", { class: "badge accent", text: "고정" }) : el("span", { text: "" }),
        ].filter(x => x.textContent !== "")),
        el("div", { class: "cardBody", text: g.desc || "설명이 없습니다." }),
      ]);

      card.addEventListener("click", () => {
        viewState.activeGalleryId = g.id;
        viewState.activeGalleryOwnerId = ownerId;
        renderAll();
      });

      grid.appendChild(card);
    }
    return grid;
  }

  function renderPostsView(galleryOwnerId, galleryId, q) {
    const ownerName = getUserName(galleryOwnerId);

    const posts = listPostsInGallery(galleryOwnerId, galleryId, { includeDeleted: false })
      .filter(({ p, ownerName: authorName }) => {
        const hay = `${p.title || ""}\n${p.content || ""}\n${authorName || ""}`.toLowerCase();
        return !q || hay.includes(q);
      });

    posts.sort((a, b) => String(b.p.updatedAt || "").localeCompare(String(a.p.updatedAt || "")));

    if (posts.length === 0) {
      return el("div", { class: "muted", text: "게시물이 없습니다. 새 게시물을 만들어보세요." });
    }

    if (viewState.viewMode === "list") {
      const list = el("div", { class: "list" });
      for (const { ownerId: authorId, ownerName: authorName, p } of posts) {
        const row = el("div", { class: "listRow" }, [
          el("div", { class: "listLeft" }, [
            el("div", { class: "listTitle", text: p.title || "제목 없음" }),
            el("div", { class: "listSub" }, [
              el("span", { text: `작성자: ${authorName}` }),
              el("span", { text: `소유 갤러리: ${ownerName}` }),
              el("span", { text: `업데이트: ${(p.updatedAt || "").slice(0, 10)}` }),
            ]),
          ]),
          el("div", { class: "listRight" }, [
            el("span", { class: "badge", text: `댓글 ${listCommentsForPost(p.id).length}` }),
          ]),
        ]);

        row.addEventListener("click", () => openPostModal({ mode: "view", authorId, pid: p.id }));
        list.appendChild(row);
      }
      return list;
    }

    const grid = el("div", { class: "grid" });
    for (const { ownerId: authorId, ownerName: authorName, p } of posts) {
      const card = el("div", { class: "card" }, [
        el("div", { class: "cardTitle", text: p.title || "제목 없음" }),
        el("div", { class: "cardMeta" }, [
          el("span", { class: "badge", text: `작성자: ${authorName}` }),
          el("span", { class: "badge", text: `댓글 ${listCommentsForPost(p.id).length}` }),
          el("span", { class: "badge", text: `업데이트 ${String(p.updatedAt || "").slice(0, 10)}` }),
        ]),
        el("div", { class: "cardBody", text: (p.content || "").trim() || "내용이 없습니다." }),
      ]);

      card.addEventListener("click", () => openPostModal({ mode: "view", authorId, pid: p.id }));
      grid.appendChild(card);
    }
    return grid;
  }

  function renderTrashView(q) {
    const wrap = document.createElement("div");

    // Deleted galleries
    const gEntries = listAllGalleryEntries({ includeDeleted: true })
      .filter(({ g }) => !!g.deletedAt)
      .filter(({ g, ownerName }) => {
        const hay = `${g.title || ""}\n${g.desc || ""}\n${ownerName || ""}`.toLowerCase();
        return !q || hay.includes(q);
      })
      .sort((a, b) => String(b.g.deletedAt || "").localeCompare(String(a.g.deletedAt || "")));

    wrap.appendChild(el("div", { class: "muted small", text: "삭제된 갤러리" }));
    if (gEntries.length === 0) {
      wrap.appendChild(el("div", { class: "muted", text: "삭제된 갤러리가 없습니다." }));
    } else {
      const list = el("div", { class: "list" });
      for (const { ownerId, ownerName, g } of gEntries) {
        const row = el("div", { class: "listRow" }, [
          el("div", { class: "listLeft" }, [
            el("div", { class: "listTitle", text: `${g.icon || "🖼️"} ${g.title}` }),
            el("div", { class: "listSub" }, [
              el("span", { text: `소유자: ${ownerName}` }),
              el("span", { text: `삭제: ${(g.deletedAt || "").slice(0, 10)}` }),
            ]),
          ]),
          el("div", { class: "listRight" }, [
            btn("복원", "btnGhost", () => {
              if (!canManage(ownerId)) return toast({ title: "권한 없음", message: "복원할 수 없습니다." });
              restoreGallery(ownerId, g.id);
              toast({ title: "복원", message: "갤러리를 복원했습니다." });
              renderAll();
            }),
            btn("영구 삭제", "btnGhost danger", () => {
              if (!canManage(ownerId)) return toast({ title: "권한 없음", message: "영구 삭제할 수 없습니다." });
              confirmDanger("갤러리를 영구 삭제할까요?", "갤러리 및 하위 게시물이 완전히 삭제됩니다.", () => {
                purgeGallery(ownerId, g.id);
                toast({ title: "삭제", message: "영구 삭제했습니다." });
                renderAll();
              });
            }),
          ])
        ]);
        list.appendChild(row);
      }
      wrap.appendChild(list);
    }

    // Deleted posts (across all authors)
    const pEntries = [];
    for (const authorId of Object.keys(state.userData || {})) {
      const ud = ensureUserData(authorId);
      for (const p of Object.values(ud.posts || {})) {
        if (!p.deletedAt) continue;
        const authorName = getUserName(authorId);
        const hay = `${p.title || ""}\n${p.content || ""}\n${authorName || ""}`.toLowerCase();
        if (q && !hay.includes(q)) continue;
        pEntries.push({ authorId, authorName, ud, p });
      }
    }
    pEntries.sort((a, b) => String(b.p.deletedAt || "").localeCompare(String(a.p.deletedAt || "")));

    wrap.appendChild(el("div", { class: "muted small", text: "삭제된 게시물" }));
    if (pEntries.length === 0) {
      wrap.appendChild(el("div", { class: "muted", text: "삭제된 게시물이 없습니다." }));
    } else {
      const list = el("div", { class: "list" });
      for (const { authorId, authorName, p } of pEntries) {
        const row = el("div", { class: "listRow" }, [
          el("div", { class: "listLeft" }, [
            el("div", { class: "listTitle", text: p.title || "제목 없음" }),
            el("div", { class: "listSub" }, [
              el("span", { text: `작성자: ${authorName}` }),
              el("span", { text: `삭제: ${(p.deletedAt || "").slice(0, 10)}` }),
            ]),
          ]),
          el("div", { class: "listRight" }, [
            btn("복원", "btnGhost", () => {
              if (!canManage(authorId)) return toast({ title: "권한 없음", message: "복원할 수 없습니다." });
              restorePost(authorId, p.id);
              renderAll();
            }),
            btn("영구 삭제", "btnGhost danger", () => {
              if (!canManage(authorId)) return toast({ title: "권한 없음", message: "영구 삭제할 수 없습니다." });
              confirmDanger("게시물을 영구 삭제할까요?", "게시물이 완전히 삭제됩니다.", () => {
                purgePost(authorId, p.id);
                toast({ title: "삭제", message: "영구 삭제했습니다." });
                renderAll();
              });
            }),
          ])
        ]);
        list.appendChild(row);
      }
      wrap.appendChild(list);
    }

    return wrap;
  }

  // =========================================================
  // Modals: Gallery / Post / Comment
  // =========================================================
  function openGalleryModal({ mode, ownerId, gid } = {}) {
    const isEdit = mode === "edit";
    const isCreate = mode === "create";

    let ctx = null;
    let g = null;

    if (isEdit) {
      ctx = resolveGalleryCtx(gid, ownerId);
      if (!ctx || !ctx.g) return toast({ title: "오류", message: "대상을 찾지 못했습니다." });
      if (!canManage(ctx.ownerId)) return toast({ title: "권한 없음", message: "이 갤러리를 수정할 수 없습니다." });
      ownerId = ctx.ownerId;
      g = ctx.g;
    } else {
      ownerId = viewState.userId; // create: always own
    }

    const body = document.createElement("div");

    const title = el("label", { class: "field" }, [
      el("span", { class: "label", text: "갤러리 제목" }),
      el("input", { attrs: { id: "mGalleryTitle", type: "text", required: "true", maxlength: "40" } })
    ]);
    const desc = el("label", { class: "field" }, [
      el("span", { class: "label", text: "설명" }),
      el("textarea", { attrs: { id: "mGalleryDesc", maxlength: "300" } })
    ]);
    const icon = el("label", { class: "field" }, [
      el("span", { class: "label", text: "아이콘(이모지)" }),
      el("input", { attrs: { id: "mGalleryIcon", type: "text", maxlength: "4" } })
    ]);
    const color = el("label", { class: "field" }, [
      el("span", { class: "label", text: "색상(HEX, 예: #6EE7FF)" }),
      el("input", { attrs: { id: "mGalleryColor", type: "text", maxlength: "7" } })
    ]);
    const pinned = el("label", { class: "checkbox" }, [
      el("input", { attrs: { id: "mGalleryPinned", type: "checkbox" } }),
      el("span", { text: "고정" })
    ]);

    body.append(title, desc, icon, color, el("div", { class: "row" }, [pinned]));

    openModal({
      title: isCreate ? "새 갤러리" : "갤러리 편집",
      bodyEl: body,
      footerEls: [
        btn("취소", "btnGhost", () => closeModal()),
        btn(isCreate ? "생성" : "저장", "btnPrimary", () => {
          const t = $("#mGalleryTitle").value.trim();
          const d = $("#mGalleryDesc").value.trim();
          const ic = ($("#mGalleryIcon").value || "🖼️").trim();
          const co = normalizeHex($("#mGalleryColor").value || "#6EE7FF");
          const pi = $("#mGalleryPinned").checked;

          if (!t) return toast({ title: "확인", message: "제목을 입력하세요." });

          if (isCreate) {
            const newG = createGallery(ownerId, { title: t, desc: d, icon: ic, color: co, pinned: pi });
            if (!newG) return;
            viewState.activeGalleryId = newG.id;
            viewState.activeGalleryOwnerId = ownerId;
            toast({ title: "생성", message: "갤러리를 생성했습니다." });
            closeModal();
            renderAll();
            return;
          }

          updateGallery(ownerId, gid, { title: t, desc: d, icon: ic, color: co, pinned: pi });
          toast({ title: "저장", message: "갤러리를 저장했습니다." });
          closeModal();
          renderAll();
        }),
      ],
    });

    if (isEdit) {
      $("#mGalleryTitle").value = g.title || "";
      $("#mGalleryDesc").value = g.desc || "";
      $("#mGalleryIcon").value = g.icon || "🖼️";
      $("#mGalleryColor").value = g.color || "#6EE7FF";
      $("#mGalleryPinned").checked = !!g.pinned;
    } else {
      $("#mGalleryIcon").value = "🖼️";
      $("#mGalleryColor").value = normalizeHex(ensureUserData(viewState.userId).settings.accent || "#6EE7FF");
    }
  }

  function renderCommentsSection(postId) {
    const box = el("div", { class: "commentBox" });

    const comments = listCommentsForPost(postId, { includeDeleted: false });

    const header = el("div", { class: "commentHeader" }, [
      el("div", { class: "commentTitle", text: `댓글 (${comments.length})` }),
      el("div", { class: "muted small", text: "수정/삭제는 작성자만 가능" }),
    ]);

    const list = el("div", { class: "commentList" });

    if (comments.length === 0) {
      list.appendChild(el("div", { class: "muted", text: "댓글이 없습니다." }));
    } else {
      for (const { ownerId: authorId, ownerName, c } of comments) {
        const item = el("div", { class: "commentItem" });

        const meta = el("div", { class: "commentMeta" }, [
          el("div", { class: "commentAuthor", text: `작성자: ${ownerName}` }),
          el("div", { class: "commentTime", text: (c.updatedAt || c.createdAt || "").slice(0, 19).replace("T", " ") }),
        ]);

        const text = el("div", { class: "commentText", text: c.text || "" });

        const actions = el("div", { class: "commentActions" });

        if (canManage(authorId)) {
          actions.appendChild(btn("수정", "btnGhost", () => openCommentEditModal({ authorId, cid: c.id, postId })));
          actions.appendChild(btn("삭제", "btnGhost danger", () => {
            confirmDanger("댓글을 삭제할까요?", "삭제 후 복원은 제공하지 않습니다.", () => {
              deleteCommentSoft(authorId, c.id);
              toast({ title: "삭제", message: "댓글을 삭제했습니다." });
              // rerender modal content: simplest is reopen post modal
              closeModal();
              openPostModal({ mode: "view", authorId: null, pid: postId, authorHint: null });
            });
          }));
        }

        item.append(meta, text);
        if (actions.childNodes.length > 0) item.appendChild(actions);
        list.appendChild(item);
      }
    }

    const composer = el("div", { class: "commentComposer" }, [
      el("div", { class: "muted small", text: "댓글 작성" }),
      el("textarea", { attrs: { id: "commentDraft", maxlength: "1000", placeholder: "댓글을 입력하세요 (최대 1000자)" } }),
      el("div", { class: "row" }, [
        btn("등록", "btnPrimary", () => {
          const t = ($("#commentDraft").value || "").trim();
          if (!t) return toast({ title: "확인", message: "댓글 내용을 입력하세요." });
          createComment(viewState.userId, postId, t);
          toast({ title: "등록", message: "댓글을 등록했습니다." });
          closeModal();
          // reopen post modal to show updated comments
          openPostModal({ mode: "view", authorId: null, pid: postId, authorHint: null });
        })
      ])
    ]);

    box.append(header, list, composer);
    return box;
  }

  function openCommentEditModal({ authorId, cid, postId }) {
    const ud = ensureUserData(authorId);
    const c = ud.comments?.[cid];
    if (!c || c.deletedAt) return toast({ title: "오류", message: "댓글을 찾지 못했습니다." });
    if (!canManage(authorId)) return toast({ title: "권한 없음", message: "수정할 수 없습니다." });

    const body = el("div", {}, [
      el("label", { class: "field" }, [
        el("span", { class: "label", text: "댓글 수정" }),
        el("textarea", { attrs: { id: "mCommentText", maxlength: "1000" } }),
      ])
    ]);

    openModal({
      title: "댓글 수정",
      bodyEl: body,
      footerEls: [
        btn("취소", "btnGhost", () => closeModal()),
        btn("저장", "btnPrimary", () => {
          const t = ($("#mCommentText").value || "").trim();
          if (!t) return toast({ title: "확인", message: "내용을 입력하세요." });
          updateComment(authorId, cid, { text: t });
          toast({ title: "저장", message: "댓글을 수정했습니다." });
          closeModal();
          // reopen post modal
          openPostModal({ mode: "view", authorId: null, pid: postId, authorHint: null });
        })
      ]
    });

    $("#mCommentText").value = c.text || "";
  }

  function openPostModal({ mode, authorId, pid, authorHint } = {}) {
    const isView = mode === "view";
    const isCreate = mode === "create";
    const isEdit = mode === "edit";

    let pctx = null;
    let p = null;
    let authorRealId = authorId || authorHint || null;

    if (isView || isEdit) {
      pctx = resolvePostCtx(pid, authorRealId);
      if (!pctx || !pctx.p) return toast({ title: "오류", message: "게시물을 찾지 못했습니다." });
      authorRealId = pctx.ownerId;
      p = pctx.p;
    }

    if (isView) {
      // show post + comments
      const gctx = resolveGalleryCtx(p.galleryId, p.galleryOwnerId);
      const galleryTitle = gctx?.g?.title || "갤러리";
      const galleryOwnerName = getUserName(p.galleryOwnerId);
      const authorName = getUserName(authorRealId);

      const body = document.createElement("div");

      const title = el("label", { class: "field" }, [
        el("span", { class: "label", text: "제목" }),
        el("input", { attrs: { id: "mPostTitle", type: "text", maxlength: "80", disabled: "true" } }),
      ]);
      const content = el("label", { class: "field" }, [
        el("span", { class: "label", text: "내용" }),
        el("textarea", { attrs: { id: "mPostContent", maxlength: "4000", disabled: "true" } }),
      ]);

      body.append(title, content);
      body.appendChild(el("div", { class: "muted small", text: `작성자: ${authorName} · 소유 갤러리: ${galleryOwnerName} · 갤러리: ${galleryTitle}` }));

      // comments section
      body.appendChild(renderCommentsSection(p.id));

      const footer = [btn("닫기", "btnGhost", () => closeModal())];

      if (canManage(authorRealId)) {
        footer.push(btn("편집", "btnGhost", () => {
          closeModal();
          openPostModal({ mode: "edit", authorId: authorRealId, pid: p.id });
        }));
        footer.push(btn("삭제", "btnGhost danger", () => {
          confirmDanger("게시물을 삭제할까요?", "휴지통으로 이동합니다.", () => {
            deletePostSoft(authorRealId, p.id);
            toast({ title: "삭제", message: "게시물을 삭제했습니다." });
            closeModal();
            renderAll();
          });
        }));
      }

      openModal({
        title: `게시물 보기 · ${galleryTitle}`,
        bodyEl: body,
        footerEls: footer,
      });

      $("#mPostTitle").value = p.title || "";
      $("#mPostContent").value = p.content || "";
      return;
    }

    if (isCreate) {
      // create in current selected gallery (can be others' gallery)
      const gx = resolveGalleryCtx(viewState.activeGalleryId, viewState.activeGalleryOwnerId);
      if (!gx || !gx.g || gx.g.deletedAt) {
        toast({ title: "안내", message: "먼저 유효한 갤러리를 선택하세요." });
        return;
      }

      const galleryTitle = gx.g.title || "갤러리";
      const galleryOwnerName = getUserName(gx.ownerId);

      const body = document.createElement("div");
      body.appendChild(el("div", { class: "muted small", text: `대상 갤러리: ${galleryTitle} · 소유자: ${galleryOwnerName}` }));

      const title = el("label", { class: "field" }, [
        el("span", { class: "label", text: "제목" }),
        el("input", { attrs: { id: "mPostTitle", type: "text", maxlength: "80" } })
      ]);
      const content = el("label", { class: "field" }, [
        el("span", { class: "label", text: "내용" }),
        el("textarea", { attrs: { id: "mPostContent", maxlength: "4000" } })
      ]);

      body.append(title, content);

      openModal({
        title: `새 게시물 · ${galleryTitle}`,
        bodyEl: body,
        footerEls: [
          btn("취소", "btnGhost", () => closeModal()),
          btn("생성", "btnPrimary", () => {
            const t = ($("#mPostTitle").value || "").trim();
            const c = ($("#mPostContent").value || "").trim();
            if (!t) return toast({ title: "확인", message: "제목을 입력하세요." });

            const np = createPost(viewState.userId, {
              galleryOwnerId: gx.ownerId,
              galleryId: gx.g.id,
              title: t,
              content: c,
            });
            if (!np) return;

            toast({ title: "생성", message: "게시물을 생성했습니다." });
            closeModal();
            renderAll();
          }),
        ],
      });

      return;
    }

    if (isEdit) {
      // edit only by author or admin
      if (!pctx || !p) {
        const tmp = resolvePostCtx(pid, authorId);
        if (!tmp) return toast({ title: "오류", message: "게시물을 찾지 못했습니다." });
        pctx = tmp;
        p = tmp.p;
        authorRealId = tmp.ownerId;
      }
      if (!canManage(authorRealId)) return toast({ title: "권한 없음", message: "수정할 수 없습니다." });

      const gctx = resolveGalleryCtx(p.galleryId, p.galleryOwnerId);
      const galleryTitle = gctx?.g?.title || "갤러리";

      const body = document.createElement("div");
      const title = el("label", { class: "field" }, [
        el("span", { class: "label", text: "제목" }),
        el("input", { attrs: { id: "mPostTitle", type: "text", maxlength: "80" } })
      ]);
      const content = el("label", { class: "field" }, [
        el("span", { class: "label", text: "내용" }),
        el("textarea", { attrs: { id: "mPostContent", maxlength: "4000" } })
      ]);
      body.append(title, content);

      openModal({
        title: `게시물 편집 · ${galleryTitle}`,
        bodyEl: body,
        footerEls: [
          btn("취소", "btnGhost", () => closeModal()),
          btn("저장", "btnPrimary", () => {
            const t = ($("#mPostTitle").value || "").trim();
            const c = ($("#mPostContent").value || "").trim();
            if (!t) return toast({ title: "확인", message: "제목을 입력하세요." });
            updatePost(authorRealId, p.id, { title: t, content: c });
            toast({ title: "저장", message: "게시물을 저장했습니다." });
            closeModal();
            renderAll();
          }),
        ],
      });

      $("#mPostTitle").value = p.title || "";
      $("#mPostContent").value = p.content || "";
      return;
    }
  }

  // =========================================================
  // Auth
  // =========================================================
  function enterApp() {
    $("#authWrap").classList.add("isHidden");
    $("#appWrap").classList.remove("isHidden");
    renderAll();
  }

  function exitToAuth() {
    $("#appWrap").classList.add("isHidden");
    $("#authWrap").classList.remove("isHidden");
    viewState.userId = null;
    viewState.activeGalleryId = null;
    viewState.activeGalleryOwnerId = null;
    viewState.showTrash = false;
    viewState.query = "";
  }

  async function login(username, password, remember) {
    const uid = state.usernameIndex?.[username];
    if (!uid || !state.users?.[uid]) {
      toast({ title: "로그인 실패", message: "아이디 또는 비밀번호가 올바르지 않습니다." });
      return false;
    }
    const user = state.users[uid];
    const salt = b64ToBytes(user.saltB64);
    const hashTry = await deriveHashB64(password, salt);

    if (hashTry !== user.hashB64) {
      toast({ title: "로그인 실패", message: "아이디 또는 비밀번호가 올바르지 않습니다." });
      return false;
    }

    viewState.userId = uid;

    const ud = ensureUserData(uid);
    applyTheme(ud.settings.theme || "dark");
    applyAccent(ud.settings.accent || "#6EE7FF");
    viewState.viewMode = ud.settings.viewMode || "grid";

    if (remember) localStorage.setItem(REMEMBER_KEY, uid);
    else localStorage.removeItem(REMEMBER_KEY);

    toast({ title: "로그인", message: `${username} 님 환영합니다.` });
    enterApp();
    return true;
  }

  async function signup(username, password) {
    if (!isValidUsername(username)) {
      toast({ title: "회원가입 실패", message: "아이디 형식이 올바르지 않습니다." });
      return false;
    }
    if (state.usernameIndex?.[username]) {
      toast({ title: "회원가입 실패", message: "이미 존재하는 아이디입니다." });
      return false;
    }

    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const hashB64 = await deriveHashB64(password, salt);

    const userId = safeId("u_");
    state.users[userId] = {
      userId,
      username,
      saltB64: bytesToB64(salt),
      hashB64,
      createdAt: nowISO(),
      role: "user",
    };
    state.usernameIndex[username] = userId;
    ensureUserData(userId);
    saveState();

    toast({ title: "회원가입", message: "계정이 생성되었습니다. 로그인하세요." });
    return true;
  }

  function logout() {
    localStorage.removeItem(REMEMBER_KEY);
    closeUserMenu();
    exitToAuth();
    toast({ title: "로그아웃", message: "로그아웃되었습니다." });
  }

  // =========================================================
  // Import / Export
  // =========================================================
  function exportJson() {
    const blob = new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `offline_gallery_export_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function importJson() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "application/json";
    input.addEventListener("change", async () => {
      const f = input.files?.[0];
      if (!f) return;
      const text = await f.text();
      try {
        const obj = JSON.parse(text);
        if (!obj || typeof obj !== "object") throw new Error("bad json");
        obj.users ||= {};
        obj.usernameIndex ||= {};
        obj.userData ||= {};
        localStorage.setItem(STORAGE_KEY, JSON.stringify(obj));
        location.reload();
      } catch (e) {
        toast({ title: "가져오기 실패", message: "JSON 형식이 올바르지 않습니다." });
      }
    });
    input.click();
  }

  // =========================================================
  // Bind UI
  // =========================================================
  function bindAuthUI() {
    $("#tabLogin").addEventListener("click", () => {
      $("#tabLogin").classList.add("isActive");
      $("#tabSignup").classList.remove("isActive");
      $("#formLogin").classList.remove("isHidden");
      $("#formSignup").classList.add("isHidden");
    });

    $("#tabSignup").addEventListener("click", () => {
      $("#tabSignup").classList.add("isActive");
      $("#tabLogin").classList.remove("isActive");
      $("#formSignup").classList.remove("isHidden");
      $("#formLogin").classList.add("isHidden");
    });

    $("#formLogin").addEventListener("submit", async (e) => {
      e.preventDefault();
      const u = $("#loginId").value.trim();
      const p = $("#loginPw").value;
      const remember = $("#rememberMe").checked;
      await login(u, p, remember);
    });

    $("#formSignup").addEventListener("submit", async (e) => {
      e.preventDefault();
      const u = $("#signupId").value.trim();
      const p = $("#signupPw").value;
      const p2 = $("#signupPw2").value;

      if (p !== p2) return toast({ title: "회원가입 실패", message: "비밀번호가 일치하지 않습니다." });
      if (p.length < 6) return toast({ title: "회원가입 실패", message: "비밀번호는 6자 이상이어야 합니다." });

      const ok = await signup(u, p);
      if (ok) $("#tabLogin").click();
    });
  }

  function bindAppUI() {
    // menu open/close
    $("#btnUserMenu").addEventListener("click", () => {
      if (!viewState.userId) return;
      const open = !$("#userMenuPanel").classList.contains("isHidden");
      if (open) closeUserMenu();
      else openUserMenu();
    });

    $("#menuBackdrop").addEventListener("click", () => closeUserMenu());

    // global key
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        closeUserMenu();
        closeModal();
      }
    });

    // menu: theme
    $("#btnThemeDark").addEventListener("click", () => {
      if (!viewState.userId) return;
      const ud = ensureUserData(viewState.userId);
      ud.settings.theme = "dark";
      saveState();
      applyTheme("dark");
      toast({ title: "테마", message: "다크 모드가 적용되었습니다." });
    });

    $("#btnThemeLight").addEventListener("click", () => {
      if (!viewState.userId) return;
      const ud = ensureUserData(viewState.userId);
      ud.settings.theme = "light";
      saveState();
      applyTheme("light");
      toast({ title: "테마", message: "라이트 모드가 적용되었습니다." });
    });

    // menu: accent RGB sync
    const syncPair = (sliderId, numId) => {
      const s = $("#" + sliderId);
      const n = $("#" + numId);
      if (!s || !n) return;
      s.addEventListener("input", () => {
        n.value = s.value;
        updateAccentPreviewFromRgb();
      });
      n.addEventListener("input", () => {
        n.value = String(clampInt(n.value, 0, 255));
        s.value = n.value;
        updateAccentPreviewFromRgb();
      });
    };
    syncPair("rgbR", "rgbRNum");
    syncPair("rgbG", "rgbGNum");
    syncPair("rgbB", "rgbBNum");

    $("#btnAccentApply").addEventListener("click", () => {
      if (!viewState.userId) return;
      const hex = updateAccentPreviewFromRgb();
      const ud = ensureUserData(viewState.userId);
      ud.settings.accent = hex;
      saveState();
      applyAccent(hex);
      toast({ title: "색상", message: "포인트 색상을 저장했습니다." });
    });

    $("#btnAccentReset").addEventListener("click", () => {
      if (!viewState.userId) return;
      setRgbUi(110, 231, 255);
      const hex = updateAccentPreviewFromRgb();
      const ud = ensureUserData(viewState.userId);
      ud.settings.accent = hex;
      saveState();
      applyAccent(hex);
      toast({ title: "색상", message: "기본값으로 복원했습니다." });
    });

    $("#btnExport").addEventListener("click", () => exportJson());
    $("#btnImport").addEventListener("click", () => importJson());
    $("#btnLogout").addEventListener("click", () => logout());

    // sidebar search
    $("#searchInput").addEventListener("input", () => {
      viewState.query = $("#searchInput").value || "";
      renderAll();
    });

    $("#btnAllGalleries").addEventListener("click", () => {
      viewState.showTrash = false;
      viewState.activeGalleryId = null;
      viewState.activeGalleryOwnerId = null;
      renderAll();
    });

    $("#btnTrash").addEventListener("click", () => {
      viewState.showTrash = true;
      viewState.activeGalleryId = null;
      viewState.activeGalleryOwnerId = null;
      renderAll();
    });

    $("#btnViewGrid").addEventListener("click", () => {
      if (!viewState.userId) return;
      viewState.viewMode = "grid";
      const ud = ensureUserData(viewState.userId);
      ud.settings.viewMode = "grid";
      saveState();
      renderAll();
    });

    $("#btnViewList").addEventListener("click", () => {
      if (!viewState.userId) return;
      viewState.viewMode = "list";
      const ud = ensureUserData(viewState.userId);
      ud.settings.viewMode = "list";
      saveState();
      renderAll();
    });

    // actions
    $("#btnNewGallery").addEventListener("click", () => {
      if (!viewState.userId) return;
      if (viewState.showTrash) return toast({ title: "안내", message: "휴지통에서는 생성할 수 없습니다." });
      openGalleryModal({ mode: "create" });
    });

    $("#btnNewPost").addEventListener("click", () => {
      if (!viewState.userId) return;
      if (viewState.showTrash) return toast({ title: "안내", message: "휴지통에서는 생성할 수 없습니다." });
      if (!viewState.activeGalleryId) return toast({ title: "안내", message: "먼저 갤러리를 선택하세요." });
      openPostModal({ mode: "create" }); // can create in others' gallery
    });

    $("#btnEditGallery").addEventListener("click", () => {
      if (!viewState.userId) return;
      if (!viewState.activeGalleryId) return;
      const ctx = resolveGalleryCtx(viewState.activeGalleryId, viewState.activeGalleryOwnerId);
      if (!ctx) return;
      openGalleryModal({ mode: "edit", ownerId: ctx.ownerId, gid: ctx.g.id });
    });

    $("#btnDeleteGallery").addEventListener("click", () => {
      if (!viewState.userId) return;
      if (!viewState.activeGalleryId) return;
      const ctx = resolveGalleryCtx(viewState.activeGalleryId, viewState.activeGalleryOwnerId);
      if (!ctx) return;

      if (!canManage(ctx.ownerId)) return toast({ title: "권한 없음", message: "삭제할 수 없습니다." });

      confirmDanger("갤러리를 삭제할까요?", "휴지통으로 이동하며, 이 갤러리의 게시물도 함께 삭제됩니다.", () => {
        deleteGallerySoft(ctx.ownerId, ctx.g.id);
        toast({ title: "삭제", message: "갤러리를 삭제했습니다." });
        viewState.activeGalleryId = null;
        viewState.activeGalleryOwnerId = null;
        renderAll();
      });
    });

    // modal close
    $("#btnModalClose").addEventListener("click", () => closeModal());
    $("#modalBackdrop").addEventListener("click", () => closeModal());
  }

  // =========================================================
  // Boot
  // =========================================================
  document.addEventListener("DOMContentLoaded", () => {
    bindAuthUI();
    bindAppUI();

    // auto login
    const remembered = localStorage.getItem(REMEMBER_KEY);
    if (remembered && state.users?.[remembered]) {
      viewState.userId = remembered;
      const ud = ensureUserData(viewState.userId);
      applyTheme(ud.settings.theme || "dark");
      applyAccent(ud.settings.accent || "#6EE7FF");
      viewState.viewMode = ud.settings.viewMode || "grid";
      enterApp();
      toast({ title: "자동 로그인", message: `${state.users[remembered].username} 님으로 로그인되었습니다.` });
      return;
    }

    exitToAuth();
  });
})();
