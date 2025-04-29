import { useQuery } from '@tanstack/react-query';
import { Outlet, createRootRoute } from '@tanstack/react-router';
import { useEffect } from 'react';
import { toast } from 'sonner';
import { DotsBackground } from '~/components/DotsBackground';
import { Navbar } from '~/components/NavBar';
import { Loading } from '~/components/pages/Loading';
import { NotFound } from '~/components/pages/NotFound';
import { Sonner } from '~/components/ui/Sonner';
import { appInfoOptions } from '~/queries/app-info';
import { userDataOptions } from '~/queries/user';
import { useServerStore } from '~/stores/server-store';
import { useThemeStore } from '~/stores/theme-store';
import { useUserStore } from '~/stores/user-store';

export const Route = createRootRoute({
  notFoundComponent: NotFound,
  pendingComponent: Loading,
  component: Root,
});

function Root() {
  const theme = useThemeStore((state) => state.theme);
  const setUser = useUserStore((state) => state.setUser);
  const server = useServerStore((state) => state.server);
  const setAppInfo = useServerStore((state) => state.setAppInfo);
  const { data: userData, isFetching: isUserDataFetching, error: userDataError } = useQuery(userDataOptions(server));
  const { data: appInfo, isFetching: isAppInfoFetching, error: appInfoError } = useQuery(appInfoOptions(server));

  useEffect(() => {
    const isValid = userData && !isUserDataFetching && !userDataError;
    setUser(isValid ? userData : null);
    toast.info(isValid ? 'User data loaded ✅' : 'User data not found ❌', { duration: 1000 });
  }, [userData, isUserDataFetching, userDataError, setUser]);

  useEffect(() => {
    const isValid = appInfo && !isAppInfoFetching && !appInfoError;
    setAppInfo(isValid ? appInfo : null);
  }, [appInfo, isAppInfoFetching, appInfoError, setAppInfo]);

  if (isUserDataFetching || isAppInfoFetching) {
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
