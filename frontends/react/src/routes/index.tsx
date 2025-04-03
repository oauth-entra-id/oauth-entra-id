import { createFileRoute } from '@tanstack/react-router';
import Confetti from 'react-confetti';
import { GitHub } from '~/components/icons/GitHub';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '~/components/ui/Card';
import { Separator } from '~/components/ui/Separator';
import { MutedText, Title } from '~/components/ui/Text';
import { useWindowDimensions } from '~/hooks/useWindowDimensions';

export const Route = createFileRoute('/')({
  component: () => {
    const { width, height } = useWindowDimensions();
    const user = {
      name: 'John Doe',
      uniqueId: '1234567890',
      email: 'john@email.com',
    };
    return (
      <>
        <div className="absolute inset-0 z-0">
          <Confetti width={width} height={height} numberOfPieces={300} recycle={false} gravity={1} friction={0.95} />
        </div>
        <div className="flex flex-col items-center justify-center space-y-8">
          <Title>
            Welcome,
            <br /> {user.name}
          </Title>
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
              <div className="flex justify-center">
                <Button variant="outline">Logout</Button>
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
          <MutedText>There you have it, secure authentication using OAuth2.0.</MutedText>
        </div>
      </>
    );
  },
});
