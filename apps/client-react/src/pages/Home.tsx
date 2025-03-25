import { useCallback, useState } from 'react';
import { FaGithub } from 'react-icons/fa6';
import { GITHUB_REPO_URL } from '~/env';
import { Button } from '~/components/ui/button';
import { Separator } from '~/components/ui/separator';
import { Confetti } from '~/components/ui/confetti';
import { Card, CardHeader, CardTitle, CardFooter, CardContent, CardDescription } from '~/components/ui/card';
import { useUserStore } from '~/stores/userStore';
import { logoutAndGetLogoutUrl } from '~/services/user';

export default function Home() {
  const { user, setUser } = useUserStore();
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const logoutUser = useCallback(async () => {
    const url = await logoutAndGetLogoutUrl();
    setUser(null);
    if (url) {
      window.open(url, '_blank');
    }
  }, [setUser]);

  const redirectToGithub = useCallback(() => {
    if (!user?.email.startsWith('xd.')) {
      setErrorMsg("Sorry, you're not allowed to access this page.");
      return;
    }
    setErrorMsg(null);
    window.open(GITHUB_REPO_URL, '_blank');
  }, [user]);

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
          <Button className="w-full" onClick={() => redirectToGithub()}>
            <FaGithub className="w-6 h-6 mr-2" />
            Checkout our Repo!
          </Button>
          {errorMsg ? <p className="text-xs text-red-500 text-center mt-2">{errorMsg}</p> : null}
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
