import { Outlet, createRootRoute, useNavigate } from '@tanstack/react-router';
import { TanStackRouterDevtools } from '@tanstack/react-router-devtools';
import { useEffect, useId } from 'react';
import { Loading } from '~/components/Loading';
import { Navbar } from '~/components/NavBar';
import { NotFound } from '~/components/NotFound';
import { getUserData } from '~/services/user';
import { useThemeStore } from '~/stores/themeStore';
import { useUserStore } from '~/stores/userStore';

export const Route = createRootRoute({
  notFoundComponent: NotFound,
  component: Root,
});

function Root() {
  const { user, setUser } = useUserStore();
  const theme = useThemeStore((state) => state.theme);
  const navigate = useNavigate();

  useEffect(() => {
    async function loadUser() {
      const user = await getUserData();
      setUser(user);
      if (user === null) navigate({ to: '/login' });
    }
    loadUser();
  }, [setUser, navigate]);
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
