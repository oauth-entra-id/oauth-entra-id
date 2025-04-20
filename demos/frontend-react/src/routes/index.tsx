import { createFileRoute } from '@tanstack/react-router';
import Confetti from 'react-confetti';
import { GitHub } from '~/components/icons/GitHub';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '~/components/ui/Card';
import { Separator } from '~/components/ui/Separator';
import { useWindowDimensions } from '~/hooks/useWindowDimensions';
import { getTokensOnBehalfOf, logoutAndGetLogoutUrl } from '~/services/user';
import { useUserStore } from '~/stores/userStore';

export const Route = createFileRoute('/')({
  component: Home,
});

function Home() {
  const { width, height } = useWindowDimensions();
  const user = useUserStore((state) => state.user);
  const setUser = useUserStore((state) => state.setUser);

  async function logout() {
    const url = await logoutAndGetLogoutUrl();
    setUser(null);
    if (url) window.open(url, '_blank');
  }

  if (!user) return null;

  return (
    <>
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
      <div className="absolute inset-0 -z-10 pointer-events-none">
        <Confetti width={width} height={height} numberOfPieces={300} recycle={false} gravity={1} friction={0.95} />
      </div>
    </>
  );
}
