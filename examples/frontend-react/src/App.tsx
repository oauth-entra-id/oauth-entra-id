import { useQuery } from '@tanstack/react-query';
import { lazy, useEffect } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { toast } from 'sonner';
import { DotsBackground } from '~/components/DotsBackground';
import { Navbar } from '~/components/NavBar';
import { Loading } from '~/components/pages/Loading';
import { Sonner } from '~/components/ui/Sonner';
import { getAppInfo } from '~/services/app-info';
import { getUserData } from '~/services/user';
import { useServerStore } from '~/stores/server-store';
import { useThemeStore } from '~/stores/theme-store';
import { useUserStore } from '~/stores/user-store';

const Home = lazy(() => import('./pages/home'));
const Login = lazy(() => import('./pages/login'));

export default function App() {
  const { user, setUser } = useUserStore();
  const theme = useThemeStore((state) => state.theme);
  const server = useServerStore((state) => state.server);
  const setAppInfo = useServerStore((state) => state.setAppInfo);

  const userData = useQuery({ queryKey: ['user', server], queryFn: getUserData });
  const appInfo = useQuery({ queryKey: ['app-info', server], queryFn: getAppInfo });

  useEffect(() => {
    if (userData.isLoading) return;

    const isValid = userData.data && !userData.error;
    setUser(isValid ? userData.data : null);
    toast.info(isValid ? 'User data loaded ✅' : 'User data not found ❌', { duration: 1000 });
  }, [userData.data, userData.isLoading, userData.error, setUser]);

  useEffect(() => {
    if (appInfo.isLoading) return;

    const isValid = appInfo.data && !appInfo.error;
    setAppInfo(isValid ? appInfo.data : null);
  }, [appInfo.data, appInfo.isLoading, appInfo.error, setAppInfo]);

  return (
    <div className={`relative z-0 w-full h-screen bg-background text-foreground overflow-x-hidden ${theme}`}>
      <div className="h-full px-4 sm:px-6 lg:px-8">
        <Navbar />
        {userData.isLoading || appInfo.isLoading || user === undefined ? (
          <Loading />
        ) : user === null ? (
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </Routes>
        ) : (
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        )}
        <DotsBackground />
      </div>
      <Sonner />
    </div>
  );
}
