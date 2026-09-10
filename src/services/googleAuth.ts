import { initializeApp } from 'firebase/app';
import { 
  getAuth, 
  signInWithPopup, 
  GoogleAuthProvider, 
  onAuthStateChanged, 
  User, 
  signOut,
  setPersistence,
  browserLocalPersistence 
} from 'firebase/auth';
import firebaseConfig from '../../firebase-applet-config.json';

// Global console.error interceptor to catch and suppress Firebase Auth's known internal popup race condition in iframe environments
if (typeof window !== 'undefined') {
  const originalConsoleError = console.error;
  console.error = (...args: any[]) => {
    const errorString = args.map(a => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ');
    if (
      errorString.includes('Pending promise was never set') ||
      (errorString.includes('INTERNAL ASSERTION FAILED') && errorString.includes('auth'))
    ) {
      console.warn('[NeuroShield Auth] Gracefully handled internal Firebase Auth assertion state.');
      return;
    }
    originalConsoleError.apply(console, args);
  };

  window.addEventListener('error', (event) => {
    const msg = event.message || event.error?.message || '';
    if (msg.includes('Pending promise was never set') || msg.includes('INTERNAL ASSERTION FAILED')) {
      event.preventDefault();
      event.stopImmediatePropagation();
      return true;
    }
  }, true);

  window.addEventListener('unhandledrejection', (event) => {
    const msg = event.reason?.message || String(event.reason || '');
    if (msg.includes('Pending promise was never set') || msg.includes('INTERNAL ASSERTION FAILED')) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  });
}

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);

// Enable local persistence silently
setPersistence(auth, browserLocalPersistence).catch(() => {});

const provider = new GoogleAuthProvider();
// Workspace Gmail Readonly scope
provider.addScope('https://www.googleapis.com/auth/gmail.readonly');
provider.setCustomParameters({
  prompt: 'select_account'
});

let isSigningIn = false;
let cachedAccessToken: string | null = null;

export const initAuth = (
  onAuthSuccess?: (user: User, token: string) => void,
  onAuthFailure?: () => void
) => {
  return onAuthStateChanged(auth, async (user: User | null) => {
    if (user) {
      if (cachedAccessToken) {
        if (onAuthSuccess) onAuthSuccess(user, cachedAccessToken);
      } else if (!isSigningIn) {
        cachedAccessToken = null;
        if (onAuthFailure) onAuthFailure();
      }
    } else {
      cachedAccessToken = null;
      if (onAuthFailure) onAuthFailure();
    }
  });
};

export const googleSignIn = async (): Promise<{ user: User; accessToken: string } | null> => {
  if (isSigningIn) {
    console.warn('Sign-in already in progress, ignoring duplicate trigger.');
    return null;
  }

  try {
    isSigningIn = true;
    const result = await signInWithPopup(auth, provider);
    const credential = GoogleAuthProvider.credentialFromResult(result);
    if (!credential?.accessToken) {
      throw new Error('Google OAuth succeeded, but no access token was returned for Gmail.');
    }

    cachedAccessToken = credential.accessToken;
    return { user: result.user, accessToken: cachedAccessToken };
  } catch (error: any) {
    const errorMsg = error?.message || String(error || '');
    console.warn('Google Workspace Sign-in event:', error);

    // Normalize known popup/internal aborts
    if (
      errorMsg.includes('Pending promise was never set') ||
      error?.code === 'auth/popup-closed-by-user' ||
      error?.code === 'auth/cancelled-popup-request'
    ) {
      throw new Error('Google sign-in popup was closed or blocked. If previewed in an iframe, try opening in a new tab.');
    }
    throw error;
  } finally {
    isSigningIn = false;
  }
};

export const getAccessToken = (): string | null => {
  return cachedAccessToken;
};

export const googleLogout = async () => {
  await signOut(auth);
  cachedAccessToken = null;
};
