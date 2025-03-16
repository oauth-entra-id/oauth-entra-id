import { lazy, Suspense, useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useThemeStore } from './stores/themeStore';
import { useUserStore } from './stores/userStore';
import Navbar from './components/navbar';
import DotPatternComponent from './components/ui/dot-pattern';
import { getUserData } from './services/user';
import Loading from './pages/Loading';
import { cn } from './lib/utils';
import './styles/global.css';

const Home = lazy(() => import('./pages/Home'));
const Login = lazy(() => import('./pages/Login'));

const AppLayout = ({ children }: { children: React.ReactNode }) => {
  const theme = useThemeStore((state) => state.theme);
  const usePrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const darkClassname = theme === 'dark' || (theme === 'system' && usePrefersDark) ? 'dark' : '';
  return (
    <div
      className={`relative w-full min-h-screen max-h-screen bg-background text-foreground overflow-x-hidden ${darkClassname}`}>
      <Suspense fallback={<Loading />}>
        <div className="min-h-full flex flex-col max-w-screen-2xl mx-auto px-4 sm:px-6 lg:px-8 w-full h-full">
          <Navbar />
          {children}
          <DotPatternComponent
            className={cn(
              '[mask-image:radial-gradient(350px_circle_at_center,white,transparent)] md:[mask-image:radial-gradient(450px_circle_at_center,white,transparent)] lg:[mask-image:radial-gradient(550px_circle_at_center,white,transparent)]',
            )}
          />
        </div>
      </Suspense>
    </div>
  );
};

export default function App() {
  const { user, setUser } = useUserStore();

  useEffect(() => {
    async function loadUserData() {
      const user = await getUserData();
      setUser(user);
    }
    loadUserData();
  }, [setUser]);

  return (
    <AppLayout>
      {user === undefined ? (
        <Loading />
      ) : user === null ? (
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="*" element={<Navigate replace to="/login" />} />
        </Routes>
      ) : (
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="*" element={<Navigate replace to="/" />} />
        </Routes>
      )}
    </AppLayout>
  );
}
