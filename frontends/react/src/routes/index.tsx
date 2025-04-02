import { createFileRoute } from '@tanstack/react-router';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '~/components/ui/Card';
import { Separator } from '~/components/ui/Separator';

export const Route = createFileRoute('/')({
  component: App,
});

function App() {
  const user = {
    name: 'John Doe',
    uniqueId: '1234567890',
    email: 'john@email.com',
  };
  return (
    <div className="mx-auto mt-4 flex flex-col items-center justify-center max-w-xl space-y-8">
      <h1 className="text-5xl font-bold text-center">
        Welcome, <div>{user.name}</div>
      </h1>
      <Card className="relative z-10 mb-6">
        <CardHeader className="px-6 pt-6 pb-2">
          <CardTitle>You are Connected! 🎉</CardTitle>
          <CardDescription>Account details using Microsoft Entra ID</CardDescription> <Separator />
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
          <Button variant="outline" className="mx-auto">
            Logout
          </Button>
        </CardContent>
        <CardFooter className="flex flex-col">
          <a href="https://github.com/oauth-entra-id/oauth-entra-id" target="_blank" rel="noopener noreferrer">
            <Button className="w-full">Checkout our Repo!</Button>
          </a>
        </CardFooter>
      </Card>
      <p className="text-sm text-muted-foreground">There you have it, secure authentication using OAuth2.0.</p>
    </div>
  );
}
