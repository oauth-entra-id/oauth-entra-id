import { useQuery } from '@tanstack/react-query';
import { Outlet, createRootRoute, useLocation, useNavigate } from '@tanstack/react-router';
import { useEffect } from 'react';
import { toast } from 'sonner';
import { DotsBackground } from '~/components/DotsBackground';
import { Navbar } from '~/components/NavBar';
import { Loading } from '~/components/pages/Loading';
import { NotFound } from '~/components/pages/NotFound';
import { Sonner } from '~/components/ui/Sonner';
import { getAppInfo } from '~/services/app-info';
import { getUserData } from '~/services/user';
import { useServerStore } from '~/stores/server-store';
import { useThemeStore } from '~/stores/theme-store';
import { useUserStore } from '~/stores/user-store';

const PUBLIC_PATHNAMES = ['/login'];

export const Route = createRootRoute({
  notFoundComponent: NotFound,
  pendingComponent: Loading,
  component: Root,
});

function Root() {
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useThemeStore((state) => state.theme);
  const setUser = useUserStore((state) => state.setUser);
  const server = useServerStore((state) => state.server);
  const setAppInfo = useServerStore((state) => state.setAppInfo);

  const userData = useQuery({
    queryKey: ['user', server],
    queryFn: getUserData,
    refetchOnWindowFocus: false,
    retry: 1,
  });

  const appInfo = useQuery({
    queryKey: ['app-info', server],
    queryFn: getAppInfo,
    refetchOnWindowFocus: false,
    retry: 1,
  });

  useEffect(() => {
    if (userData.isLoading) return;
    const isValid = userData.data && !userData.error;
    setUser(isValid ? userData.data : null);
    if (!isValid && !PUBLIC_PATHNAMES.includes(location.pathname)) {
      navigate({ to: '/login', replace: true });
    }
    toast.info(isValid ? 'User data loaded ✅' : 'User data not found ❌', { duration: 1000 });
  }, [userData.data, userData.isLoading, userData.error, setUser, navigate, location.pathname]);

  useEffect(() => {
    if (appInfo.isLoading) return;
    const isValid = appInfo.data && !appInfo.error;
    setAppInfo(isValid ? appInfo.data : null);
  }, [appInfo.data, appInfo.isLoading, appInfo.error, setAppInfo]);

  if (userData.isLoading || appInfo.isLoading) {
    return <Loading />;
  }

  return (
    <div className={`relative z-0 w-full h-screen bg-background text-foreground overflow-x-hidden ${theme}`}>
      <div className="h-full px-4 sm:px-6 lg:px-8">
        <Navbar />
        <Outlet />
        <DotsBackground />
      </div>
      <Sonner />
    </div>
  );
}
