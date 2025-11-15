import React, { useState, useEffect } from 'react';
import { initializeApp } from 'firebase/app';
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  signInWithCustomToken,
  signInAnonymously,
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  setDoc,
  getDoc,
  collection,
  query,
  onSnapshot,
} from 'firebase/firestore';
import { LogIn, UserPlus, LogOut, Loader, Home } from 'lucide-react';

// --- GLOBAL FIREBASE CONFIG & SETUP (MANDATORY) ---
// Note: These variables are automatically provided in the environment.
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : {};
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : undefined;

// --- UTILITY COMPONENTS ---

// Custom Modal for Alert/Confirmation (Instead of alert() or confirm())
const CustomModal = ({ message, onClose }) => (
  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
    <div className="bg-white p-6 rounded-xl shadow-2xl max-w-sm w-full text-center">
      <p className="text-gray-700 font-medium mb-4">{message}</p>
      <button
        onClick={onClose}
        className="px-4 py-2 bg-indigo-600 text-white font-semibold rounded-lg hover:bg-indigo-700 transition duration-150"
      >
        OK
      </button>
    </div>
  </div>
);

// --- MAIN APPLICATION COMPONENT ---

const App = () => {
  // Firebase State
  const [db, setDb] = useState(null);
  const [auth, setAuth] = useState(null);
  const [user, setUser] = useState(null); // Firebase User object
  const [userId, setUserId] = useState(null); // Primary identifier (uid or temp ID)
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [loading, setLoading] = useState(true);
  
  // UI State
  const [isLoginMode, setIsLoginMode] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [modalMessage, setModalMessage] = useState(null);

  // Firestore Data State (Example)
  const [profileData, setProfileData] = useState(null);

  // 1. FIREBASE INITIALIZATION AND AUTHENTICATION
  useEffect(() => {
    try {
      // Initialize Firebase App
      const app = initializeApp(firebaseConfig);
      const authInstance = getAuth(app);
      const dbInstance = getFirestore(app);

      setAuth(authInstance);
      setDb(dbInstance);

      // Listen for Auth State Changes
      const unsubscribe = onAuthStateChanged(authInstance, (currentUser) => {
        setUser(currentUser);
        // Determine the user ID based on auth state
        const currentUserId = currentUser ? currentUser.uid : crypto.randomUUID();
        setUserId(currentUserId);
        setIsAuthReady(true);
        setLoading(false);
      });

      // Attempt to sign in with custom token or anonymously
      const attemptSignIn = async () => {
        try {
          if (initialAuthToken) {
            await signInWithCustomToken(authInstance, initialAuthToken);
          } else {
            await signInAnonymously(authInstance);
          }
        } catch (e) {
          console.error("Error during initial sign-in:", e);
          // If custom token fails, try anonymous sign-in as fallback
          if (!authInstance.currentUser) {
             await signInAnonymously(authInstance);
          }
        }
      };
      
      attemptSignIn();
      
      // Cleanup listener on unmount
      return () => unsubscribe();
    } catch (e) {
      console.error("Firebase Initialization Error:", e);
      setError("Failed to initialize Firebase services.");
      setLoading(false);
    }
  }, []);

  // 2. FIRESTORE DATA LISTENER (Fetches profile data once auth is ready)
  useEffect(() => {
    if (!db || !userId || !isAuthReady || !user || !user.email) return;

    // Path for private user data: /artifacts/{appId}/users/{userId}/profiles/{userId}
    const profileRef = doc(db, 
      `artifacts/${appId}/users/${userId}/profiles`, 
      userId
    );

    // Set up real-time listener
    const unsubscribe = onSnapshot(profileRef, (docSnap) => {
      if (docSnap.exists()) {
        setProfileData(docSnap.data());
      } else {
        setProfileData({ email: user.email, registeredAt: new Date().toLocaleDateString() });
      }
    }, (error) => {
      console.error("Error listening to profile data:", error);
      // setModalMessage(`Error loading profile: ${error.message}`);
    });

    return () => unsubscribe();
  }, [db, userId, isAuthReady, user]); // Depend on db, userId, and user (which changes upon successful login/reg)


  // 3. AUTHENTICATION HANDLERS

  const handleAuthAction = async () => {
    if (!auth) return;
    setLoading(true);
    setError(null);

    try {
      if (isLoginMode) {
        // --- LOGIN ---
        await signInWithEmailAndPassword(auth, email, password);
        setModalMessage("Login successful! Welcome back.");
      } else {
        // --- REGISTER ---
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        const newUser = userCredential.user;

        // Save initial profile data to Firestore upon successful registration
        if (db && newUser) {
          const profileDocRef = doc(db, 
            `artifacts/${appId}/users/${newUser.uid}/profiles`, 
            newUser.uid
          );
          
          await setDoc(profileDocRef, {
            email: newUser.email,
            uid: newUser.uid,
            createdAt: new Date().toISOString(),
          }, { merge: true });
        }
        setModalMessage("Registration successful! You are now logged in.");
      }
      // Clear inputs
      setEmail('');
      setPassword('');

    } catch (e) {
      console.error("Authentication Error:", e.message);
      let friendlyError = "An unknown error occurred.";

      // Map Firebase error codes to friendly messages
      switch (e.code) {
        case 'auth/invalid-email':
          friendlyError = 'Invalid email format.';
          break;
        case 'auth/user-not-found':
        case 'auth/wrong-password':
          friendlyError = 'Invalid email or password.';
          break;
        case 'auth/email-already-in-use':
          friendlyError = 'This email is already registered.';
          break;
        case 'auth/weak-password':
          friendlyError = 'Password should be at least 6 characters.';
          break;
        default:
          friendlyError = `Authentication failed: ${e.message.split('(')[0]}`;
          break;
      }
      setError(friendlyError);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    if (!auth) return;
    setLoading(true);
    try {
      await signOut(auth);
      setModalMessage("Successfully logged out.");
      setProfileData(null); // Clear profile data on logout
    } catch (e) {
      console.error("Logout Error:", e);
      setError('Failed to log out.');
    } finally {
      setLoading(false);
    }
  };

  // --- UI RENDERING ---

  const AuthCard = (
    <div className="w-full max-w-md bg-white p-8 sm:p-10 rounded-2xl shadow-2xl border border-gray-100 transform transition-all duration-300 hover:shadow-indigo-300/50">
      <div className="flex justify-center items-center mb-6">
        <Home className="w-8 h-8 text-indigo-600 mr-2" />
        <h2 className="text-3xl font-extrabold text-gray-900">
          {isLoginMode ? 'Sign In' : 'Create Account'}
        </h2>
      </div>

      {/* Auth Mode Toggle */}
      <div className="flex justify-center mb-6 space-x-2">
        <button
          onClick={() => setIsLoginMode(true)}
          className={`flex items-center px-4 py-2 text-sm font-medium rounded-full transition-all duration-200 ${
            isLoginMode
              ? 'bg-indigo-600 text-white shadow-md'
              : 'bg-gray-100 text-gray-700 hover:bg-indigo-50 hover:text-indigo-600'
          }`}
        >
          <LogIn className="w-4 h-4 mr-2" /> Login
        </button>
        <button
          onClick={() => setIsLoginMode(false)}
          className={`flex items-center px-4 py-2 text-sm font-medium rounded-full transition-all duration-200 ${
            !isLoginMode
              ? 'bg-indigo-600 text-white shadow-md'
              : 'bg-gray-100 text-gray-700 hover:bg-indigo-50 hover:text-indigo-600'
          }`}
        >
          <UserPlus className="w-4 h-4 mr-2" /> Register
        </button>
      </div>

      {/* Input Fields */}
      <div className="space-y-4">
        <div>
          <label htmlFor="email" className="block text-sm font-medium text-gray-700">
            Email address
          </label>
          <input
            id="email"
            name="email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-indigo-500 focus:border-indigo-500 transition duration-150"
            placeholder="you@example.com"
          />
        </div>

        <div>
          <label htmlFor="password" className="block text-sm font-medium text-gray-700">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-indigo-500 focus:border-indigo-500 transition duration-150"
            placeholder="6+ characters"
          />
        </div>

        {error && (
          <div className="p-3 text-sm text-red-700 bg-red-100 rounded-lg border border-red-300" role="alert">
            {error}
          </div>
        )}

        <button
          onClick={handleAuthAction}
          disabled={loading || !email || !password}
          className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-lg shadow-lg text-lg font-semibold text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition duration-300 disabled:opacity-50 disabled:cursor-not-allowed transform hover:scale-[1.01]"
        >
          {loading ? (
            <Loader className="w-5 h-5 animate-spin mr-2" />
          ) : isLoginMode ? (
            <><LogIn className="w-5 h-5 mr-2" /> Sign In</>
          ) : (
            <><UserPlus className="w-5 h-5 mr-2" /> Register</>
          )}
        </button>
      </div>
    </div>
  );

  const Dashboard = (
    <div className="w-full max-w-3xl bg-white p-8 sm:p-10 rounded-2xl shadow-2xl border border-gray-100">
      <div className="flex justify-between items-center mb-6 border-b pb-4">
        <h2 className="text-3xl font-extrabold text-indigo-800 flex items-center">
          <Home className="w-6 h-6 mr-3 text-indigo-600" /> User Dashboard
        </h2>
        <button
          onClick={handleLogout}
          disabled={loading}
          className="flex items-center px-4 py-2 text-sm font-medium rounded-lg text-white bg-red-500 hover:bg-red-600 transition duration-150 disabled:opacity-50"
        >
          <LogOut className="w-4 h-4 mr-2" /> Logout
        </button>
      </div>

      <div className="space-y-4">
        <h3 className="text-xl font-semibold text-gray-700">Account Details</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-gray-600">
          <div className="p-4 bg-indigo-50 rounded-lg">
            <p className="font-medium text-indigo-800">Email:</p>
            <p className="truncate">{user?.email || 'N/A'}</p>
          </div>
          <div className="p-4 bg-indigo-50 rounded-lg">
            <p className="font-medium text-indigo-800">User ID (UID):</p>
            <p className="break-all text-sm font-mono">{user?.uid || userId}</p>
          </div>
        </div>

        {user?.email && (
          <>
            <h3 className="text-xl font-semibold text-gray-700 pt-4">Firestore Profile Data</h3>
            <p className="text-sm text-gray-500 mb-2">
              (Data saved to private collection: `artifacts/{appId}/users/{user.uid}/profiles/{user.uid}`)
            </p>
            <div className="p-4 bg-green-50 rounded-lg border border-green-200">
              {profileData ? (
                <pre className="whitespace-pre-wrap text-sm text-green-800 bg-white p-3 rounded-lg border">
                  {JSON.stringify(profileData, null, 2)}
                </pre>
              ) : (
                <p className="text-green-800">Loading profile data...</p>
              )}
            </div>
          </>
        )}
      </div>

      <p className="mt-8 text-center text-sm text-gray-500">
        If `user.email` is null, you are currently signed in anonymously.
      </p>
    </div>
  );

  if (loading && !isAuthReady) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="flex items-center text-lg font-medium text-indigo-600">
          <Loader className="w-6 h-6 animate-spin mr-3" /> Initializing Application...
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4">
      <div className="max-w-7xl mx-auto w-full">
        {user && user.email ? Dashboard : AuthCard}
      </div>
      <p className="mt-6 text-xs text-gray-500">
        Current App ID: <span className="font-mono">{appId}</span> |
        Current Session ID (for unauthenticated use): <span className="font-mono">{userId}</span>
      </p>
      {modalMessage && <CustomModal message={modalMessage} onClose={() => setModalMessage(null)} />}
    </div>
  );
};

export default App;