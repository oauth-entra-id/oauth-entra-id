import { Outlet, createRootRoute, useLocation, useNavigate } from '@tanstack/react-router';
import { TanStackRouterDevtools } from '@tanstack/react-router-devtools';
import { useEffect } from 'react';
import { DotsBackground } from '~/components/DotsBackground';
import { Loading } from '~/components/Loading';
import { Navbar } from '~/components/NavBar';
import { NotFound } from '~/components/NotFound';
import { ServersDropdown } from '~/components/ServersDropdown';
import { MutedText, SmallMutedText, Title } from '~/components/ui/Text';
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
  const { user, setUser } = useUserStore();
  const server = useServerStore((state) => state.server);
  const appId = useServerStore((state) => state.appId);
  const setAppId = useServerStore((state) => state.setAppId);
  const navigate = useNavigate();
  const location = useLocation();

  // biome-ignore lint/correctness/useExhaustiveDependencies: There is a correlation
  useEffect(() => {
    (async () => {
      setAppId(await getAppId());
      setUser(await getUserData());
    })();
  }, [setAppId, setUser, server]);

  useEffect(() => {
    const inLoginPage = location.pathname === '/login';
    if (!user && !inLoginPage) {
      navigate({ to: '/login' });
    } else if (user && inLoginPage) {
      navigate({ to: '/' });
    }
  }, [user, location.pathname, navigate]);

  if (user === undefined || appId === undefined) {
    return (
      <div className={theme}>
        <Loading />
      </div>
    );
  }

  return (
    <>
      <div className={`relative w-full h-screen bg-background text-foreground overflow-x-hidden ${theme}`}>
        <div className="h-full px-4 sm:px-6 lg:px-8">
          <Navbar />
          <div className="flex flex-col items-center justify-center mt-2">
            <div className="flex flex-col items-center justify-center space-y-3 z-10">
              <Title>
                Welcome,
                <br /> {user ? user.name : 'Guest'}
              </Title>
              <SmallMutedText className="mb-1">
                <span className="font-bold">App Id: </span>
                {appId}
              </SmallMutedText>
              <Outlet />
              <ServersDropdown />
              <MutedText>React demo that shows how to integrate OAuth2.0 Flow.</MutedText>
            </div>
          </div>
          <DotsBackground />
        </div>
      </div>
      <TanStackRouterDevtools />
    </>
  );
}
