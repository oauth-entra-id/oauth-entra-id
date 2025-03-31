import { useCallback } from 'react';
import { FaGithub } from 'react-icons/fa6';
import { Button } from '~/components/ui/Button';
import { Separator } from '~/components/ui/Separator';
import { Confetti } from '~/components/ui/Confetti';
import { Card, CardHeader, CardTitle, CardFooter, CardContent, CardDescription } from '~/components/ui/Card';
import { useUserStore } from '~/stores/userStore';
import { logoutAndGetLogoutUrl } from '~/services/user';

export default function Home() {
  const { user, setUser } = useUserStore();

  const logoutUser = useCallback(async () => {
    const url = await logoutAndGetLogoutUrl();
    setUser(null);
    if (url) {
      window.open(url, '_blank');
    }
  }, [setUser]);

  if (!user) return null;

  return (
    <div className="mx-auto mt-4 flex flex-col items-center justify-center max-w-xl space-y-8">
      <h1 className="text-5xl font-bold text-center">
        Welcome, <div>{user.name}</div>
      </h1>

      <Card className="relative z-10 mb-6">
        <CardHeader className="px-6 pt-6 pb-2">
          <CardTitle>You are Connected! 🎉</CardTitle>
          <CardDescription>Account details using Microsoft Entra ID</CardDescription>
          <Separator />
        </CardHeader>

        <CardContent className="space-y-1 px-6 pb-6 flex flex-col items-start text-md">
          <div>
            <span className="font-bold">Unique ID:</span> {user.uniqueId}
          </div>
          <div>
            <span className="font-bold">Email:</span> {user.email}
          </div>
          <div>
            <span className="font-bold">Name:</span> {user.name}
          </div>
          <Button variant="outline" className="mx-auto" onClick={() => logoutUser()}>
            Logout
          </Button>
        </CardContent>

        <CardFooter className="flex flex-col">
          <a href="https://github.com/oauth-entra-id/oauth-entra-id" target="_blank" rel="noopener noreferrer">
            <Button className="w-full">
              <FaGithub className="w-6 h-6 mr-2" />
              Checkout our Repo!
            </Button>
          </a>
        </CardFooter>
      </Card>
      <p className="text-sm text-muted-foreground">There you have it, secure authentication using OAuth2.0.</p>

      <Confetti
        className="absolute left-0 top-0 z-0 size-full"
        options={{ spread: 55, particleCount: 100, ticks: 250 }}
      />
    </div>
  );
}
