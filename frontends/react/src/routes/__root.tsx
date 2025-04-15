import { Outlet, createRootRoute, useLocation, useNavigate } from '@tanstack/react-router';
import { TanStackRouterDevtools } from '@tanstack/react-router-devtools';
import { useEffect, useId } from 'react';
import { Loading } from '~/components/Loading';
import { Navbar } from '~/components/NavBar';
import { NotFound } from '~/components/NotFound';
import { getAppId, getUserData } from '~/services/user';
import { useServerStore } from '~/stores/serverStore';
import { useThemeStore } from '~/stores/themeStore';
import { useUserStore } from '~/stores/userStore';

export const Route = createRootRoute({
  notFoundComponent: NotFound,
  component: Root,
});

function Root() {
  const theme = useThemeStore((state) => state.theme);
  const user = useUserStore((state) => state.user);
  const setUser = useUserStore((state) => state.setUser);
  const setAppId = useUserStore((state) => state.setAppId);
  const server = useServerStore((state) => state.server);
  const navigate = useNavigate();
  const location = useLocation();

  // biome-ignore lint/correctness/useExhaustiveDependencies: There is a correlation between the server and appId
  useEffect(() => {
    (async () => setAppId(await getAppId()))();
  }, [setAppId, server]);

  useEffect(() => {
    (async () => setUser(await getUserData()))();
  }, [setUser]);

  useEffect(() => {
    if (!user && location.pathname !== '/login') {
      navigate({ to: '/login' });
    } else if (user && location.pathname === '/login') {
      navigate({ to: '/' });
    }
  }, [user, location.pathname, navigate]);

  return (
    <>
      <div className={`relative w-full h-screen bg-background text-foreground overflow-x-hidden ${theme}`}>
        <div className="h-full px-4 sm:px-6 lg:px-8">
          <Navbar />
          <div className="flex flex-col items-center justify-center mt-2">
            {user === undefined ? <Loading /> : <Outlet />}
          </div>
          <DotsBackground />
        </div>
      </div>
      <TanStackRouterDevtools />
    </>
  );
}

function DotsBackground() {
  const id = useId();

  return (
    <svg
      aria-hidden="true"
      className="pointer-events-none absolute inset-0 size-full fill-neutral-400/80 [mask-image:radial-gradient(350px_circle_at_center,white,transparent)] md:[mask-image:radial-gradient(450px_circle_at_center,white,transparent)] lg:[mask-image:radial-gradient(550px_circle_at_center,white,transparent)]">
      <defs>
        <pattern
          x={0}
          y={0}
          width={16}
          height={16}
          id={id}
          patternContentUnits="userSpaceOnUse"
          patternUnits="userSpaceOnUse">
          <circle cx={1} cy={1} r={1} id="pattern-circle" />
        </pattern>
      </defs>
      <rect fill={`url(#${id})`} height="100%" width="100%" strokeWidth={0} />
    </svg>
  );
}
