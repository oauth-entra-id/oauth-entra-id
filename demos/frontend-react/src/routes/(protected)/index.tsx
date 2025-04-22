import { Separator } from '@radix-ui/react-dropdown-menu';
import { createFileRoute } from '@tanstack/react-router';
import Confetti from 'react-confetti';
import { ServersDropdown } from '~/components/ServersDropdown';
import { GitHub } from '~/components/icons/GitHub';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '~/components/ui/Card';
import { MutedText, SmallMutedText, Title } from '~/components/ui/Text';
import { useWindowDimensions } from '~/hooks/useWindowDimensions';
import { getTokensOnBehalfOf, logoutAndGetLogoutUrl } from '~/services/user';
import { useServerStore } from '~/stores/serverStore';
import { useUserStore } from '~/stores/userStore';

export const Route = createFileRoute('/(protected)/')({
  component: Home,
});

function Home() {
  const { width, height } = useWindowDimensions();
  const { user, setUser } = useUserStore();
  const appId = useServerStore((state) => state.appId);

  async function logout() {
    const url = await logoutAndGetLogoutUrl();
    if (url) {
      setUser(null);
      window.open(url, '_blank');
    }
  }

  if (!user) return null;

  return (
    <>
      <div className="flex flex-col items-center justify-center mt-2">
        <div className="flex flex-col items-center justify-center space-y-3 z-10">
          <Title>
            Welcome,
            <br /> {user.name}
          </Title>
          {appId && (
            <SmallMutedText className="mb-1">
              <span className="font-bold">App Id: </span>
              {appId}
            </SmallMutedText>
          )}
          <Card>
            <CardHeader>
              <CardTitle>You are Connected! 🎉</CardTitle>
              <CardDescription>Account details using Microsoft Entra ID</CardDescription>
              <Separator />
            </CardHeader>
            <CardContent>
              <div>
                <span className="font-bold">Unique ID:</span> {user.uniqueId}
              </div>
              <div>
                <span className="font-bold">Email:</span> {user.email}
              </div>
              <div>
                <span className="font-bold">Name:</span> {user.name}
              </div>
              <div className="flex justify-center w-full space-x-2 px-1">
                <Button variant="outline" className="flex-1" onClick={async () => await getTokensOnBehalfOf()}>
                  New Tokens
                </Button>
                <Button variant="destructive" className="flex-1" onClick={async () => await logout()}>
                  Logout
                </Button>
              </div>
            </CardContent>
            <CardFooter>
              <Button className="w-full mt-1" asChild>
                <a href="https://github.com/oauth-entra-id/oauth-entra-id" target="_blank" rel="noopener noreferrer">
                  <GitHub /> Checkout our Repo!
                </a>
              </Button>
            </CardFooter>
          </Card>
          <ServersDropdown />
          <MutedText>React demo that shows how to integrate OAuth2.0 Flow.</MutedText>
        </div>
      </div>

      <div className="absolute inset-0 -z-10 pointer-events-none">
        <Confetti width={width} height={height} numberOfPieces={300} recycle={false} gravity={1} friction={0.95} />
      </div>
    </>
  );
}
