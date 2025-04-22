import { Outlet, createRootRoute } from '@tanstack/react-router';
import { TanStackRouterDevtools } from '@tanstack/react-router-devtools';
import { useEffect } from 'react';
import { DotsBackground } from '~/components/DotsBackground';
import { Loading } from '~/components/Loading';
import { Navbar } from '~/components/NavBar';
import { NotFound } from '~/components/NotFound';
import { getAppInfo, getUserData } from '~/services/user';
import { useServerStore } from '~/stores/serverStore';
import { useThemeStore } from '~/stores/themeStore';
import { useUserStore } from '~/stores/userStore';

export const Route = createRootRoute({
  notFoundComponent: NotFound,
  pendingComponent: Loading,
  component: Root,
});

function Root() {
  const theme = useThemeStore((state) => state.theme);
  const { user, setUser } = useUserStore();
  const server = useServerStore((state) => state.server);
  const setAppRegs = useServerStore((state) => state.setAppRegs);

  // biome-ignore lint/correctness/useExhaustiveDependencies: There is a correlation
  useEffect(() => {
    (async () => {
      const [appId, user] = await Promise.all([getAppInfo(), getUserData()]);
      setAppRegs(appId);
      setUser(user);
    })();
  }, [setAppRegs, setUser, server]);

  if (user === undefined) return <Loading />;

  return (
    <>
      <div className={`relative z-0 w-full h-screen bg-background text-foreground overflow-x-hidden ${theme}`}>
        <div className="h-full px-4 sm:px-6 lg:px-8">
          <Navbar />
          <Outlet />
          <DotsBackground />
        </div>
      </div>
      <TanStackRouterDevtools />
    </>
  );
}
