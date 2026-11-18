import { useQuery } from '@tanstack/react-query';
import { lazy, useEffect } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router';
import { toast } from 'sonner';
import { DotsBackground } from '~/components/DotsBackground';
import { Navbar } from '~/components/NavBar';
import { Loading } from '~/components/pages/Loading';
import { Sonner } from '~/components/ui/Sonner';
import { MOBILE_RETURN_PATH } from '~/lib/mobile-storage';
import { getAppInfo } from '~/services/app-info';
import { getUserData } from '~/services/user';
import { useProviderStore } from '~/stores/provider-store';
import { useServerStore } from '~/stores/server-store';
import { useThemeStore } from '~/stores/theme-store';
import { useUserStore } from '~/stores/user-store';

const Home = lazy(() => import('./pages/home'));
const Lite = lazy(() => import('./pages/lite'));
const Login = lazy(() => import('./pages/login'));
const MobileReturn = lazy(() => import('./pages/mobile-return'));

export default function App() {
  const { pathname } = useLocation();
  const { user, setUser } = useUserStore();
  const theme = useThemeStore((state) => state.theme);
  const provider = useProviderStore((state) => state.provider);
  const server = useServerStore((state) => state.server);
  const setAppInfo = useServerStore((state) => state.setAppInfo);

  const userData = useQuery({ queryKey: ['user', server], queryFn: getUserData });
  const appInfo = useQuery({ queryKey: ['app-info', server], queryFn: getAppInfo });

  useEffect(() => {
    if (userData.isLoading) return;

    const isValid = userData.data && !userData.error;
    setUser(isValid ? userData.data : null);
    if (useProviderStore.getState().provider === 'oauth') {
      toast.info(isValid ? 'User data loaded ✅' : 'User data not found ❌', { duration: 1000 });
    }
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
        {pathname === MOBILE_RETURN_PATH ? (
          <MobileReturn />
        ) : provider === 'lite' ? (
          appInfo.isLoading ? (
            <Loading />
          ) : (
            <Lite />
          )
        ) : userData.isLoading || appInfo.isLoading || user === undefined ? (
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
