// Face embedding and hashing using MediaPipe FaceMesh.
// Computes a SHA-256 hash of normalized facial landmarks.
// The photo is never stored — only the hash leaves this function.
//
// MediaPipe FaceMesh is loaded from CDN (468 3D landmarks per face).
// For production offline deployment, self-host the WASM assets.

let faceMeshInstance = null;

async function loadFaceMesh() {
  if (faceMeshInstance) return faceMeshInstance;

  // MediaPipe's CDN bundle attaches to window, not ESM named exports.
  // Load the script, then read FaceMesh from window.
  await import(
    /* @vite-ignore */
    'https://cdn.jsdelivr.net/npm/@mediapipe/face_mesh@0.4.1633559619/face_mesh.js'
  );
  const FaceMesh = window.FaceMesh;
  if (!FaceMesh) throw new Error('MediaPipe FaceMesh failed to load from CDN');

  faceMeshInstance = new FaceMesh({
    locateFile: (file) =>
      `https://cdn.jsdelivr.net/npm/@mediapipe/face_mesh@0.4.1633559619/${file}`,
  });

  faceMeshInstance.setOptions({
    maxNumFaces: 1,
    refineLandmarks: true,
    minDetectionConfidence: 0.5,
    minTrackingConfidence: 0.5,
  });

  await new Promise((resolve, reject) => {
    faceMeshInstance.onResults((results) => resolve(results));
    // Send a tiny dummy canvas to trigger initialization
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 1;
    faceMeshInstance.send({ image: canvas }).catch(reject);
    // Resolve after timeout if the dummy result never comes back
    setTimeout(resolve, 3000);
  });

  return faceMeshInstance;
}

// ── Normalize landmarks: centre + scale to unit sphere ───────────────────────
function normalizeLandmarks(landmarks) {
  const xs = landmarks.map(l => l.x);
  const ys = landmarks.map(l => l.y);
  const zs = landmarks.map(l => l.z);

  const cx = (Math.min(...xs) + Math.max(...xs)) / 2;
  const cy = (Math.min(...ys) + Math.max(...ys)) / 2;
  const cz = (Math.min(...zs) + Math.max(...zs)) / 2;

  const maxSpan = Math.max(
    Math.max(...xs) - Math.min(...xs),
    Math.max(...ys) - Math.min(...ys),
    Math.max(...zs) - Math.min(...zs),
  ) || 1;

  // 468 landmarks × 3 coords = 1404 float32 values
  const buf = new Float32Array(landmarks.length * 3);
  for (let i = 0; i < landmarks.length; i++) {
    buf[i * 3]     = (landmarks[i].x - cx) / maxSpan;
    buf[i * 3 + 1] = (landmarks[i].y - cy) / maxSpan;
    buf[i * 3 + 2] = (landmarks[i].z - cz) / maxSpan;
  }
  return buf;
}

// ── Hash a Float32Array → hex field element (31 bytes, fits in BN254 Field) ──
async function hashEmbedding(floatArray) {
  const bytes  = new Uint8Array(floatArray.buffer);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  // Take first 31 bytes to stay within the BN254 scalar field
  const field  = new Uint8Array(digest).slice(0, 31);
  return '0x' + Array.from(field).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Detect a face in the provided image/video element and return its hash.
 * The image is processed locally — no pixels leave the browser.
 *
 * @param {HTMLImageElement|HTMLVideoElement|HTMLCanvasElement} source
 * @returns {Promise<{faceHash: string}>}
 */
export async function computeFaceHash(source) {
  const fm = await loadFaceMesh();

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Face detection timed out')), 15_000);

    fm.onResults((results) => {
      clearTimeout(timeout);
      const faces = results.multiFaceLandmarks;
      if (!faces || faces.length === 0) {
        return reject(new Error('No face detected. Please look directly at the camera.'));
      }
      const landmarks = faces[0]; // first face
      const normalized = normalizeLandmarks(landmarks);
      hashEmbedding(normalized)
        .then(faceHash => resolve({ faceHash }))
        .catch(reject);
    });

    fm.send({ image: source }).catch(reject);
  });
}

/**
 * Capture a selfie from the user's camera, compute the face hash,
 * and immediately discard the pixel data.
 *
 * @param {HTMLVideoElement} videoEl - live camera stream element
 * @returns {Promise<{faceHash: string, thumbnail: string}>}
 */
export async function captureSelfieHash(videoEl) {
  const canvas = document.createElement('canvas');
  canvas.width  = videoEl.videoWidth  || 640;
  canvas.height = videoEl.videoHeight || 480;
  canvas.getContext('2d').drawImage(videoEl, 0, 0);

  // Tiny thumbnail for UI display (128px wide), full frame not retained
  const thumb = document.createElement('canvas');
  thumb.width  = 128;
  thumb.height = Math.round(128 * canvas.height / canvas.width);
  thumb.getContext('2d').drawImage(canvas, 0, 0, thumb.width, thumb.height);
  const thumbnail = thumb.toDataURL('image/jpeg', 0.7);

  const { faceHash } = await computeFaceHash(canvas);

  // Clear the full-resolution canvas immediately
  canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);

  return { faceHash, thumbnail };
}
