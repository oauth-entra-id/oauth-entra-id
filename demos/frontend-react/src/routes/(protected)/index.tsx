import { Separator } from '@radix-ui/react-dropdown-menu';
import { ToggleGroup } from '@radix-ui/react-toggle-group';
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import Confetti from 'react-confetti';
import { AppInfo } from '~/components/AppInfo';
import { ServersDropdown } from '~/components/ServersDropdown';
import { GitHub } from '~/components/icons/GitHub';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '~/components/ui/Card';
import { MutedText, Title } from '~/components/ui/Text';
import { ToggleGroupItem } from '~/components/ui/ToggleGroup';
import { useWindowDimensions } from '~/hooks/useWindowDimensions';
import { getTokensOnBehalfOf, logoutAndGetLogoutUrl } from '~/services/user';
import { type Color, useServerStore } from '~/stores/serverStore';
import { useUserStore } from '~/stores/userStore';

export const Route = createFileRoute('/(protected)/')({
  component: Home,
});

function Home() {
  const [selectedServiceNames, setSelectedServiceNames] = useState<Color[]>([]);
  const { width, height } = useWindowDimensions();
  const { user, setUser } = useUserStore();

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
          <AppInfo />
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
              <div className="flex flex-col items-center justify-center px-1">
                <SelectServiceNames
                  selectedServiceNames={selectedServiceNames}
                  setSelectedServiceNames={setSelectedServiceNames}
                />
                <div className="flex w-full space-x-2 mt-2">
                  <Button
                    variant="outline"
                    className="flex-1"
                    onClick={async () => await getTokensOnBehalfOf({ serviceNames: selectedServiceNames })}>
                    New Tokens
                  </Button>
                  <Button variant="destructive" className="flex-1" onClick={async () => await logout()}>
                    Logout
                  </Button>
                </div>
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
        <Confetti width={width} height={height} numberOfPieces={200} recycle={false} gravity={1} friction={0.95} />
      </div>
    </>
  );
}

function SelectServiceNames({
  selectedServiceNames,
  setSelectedServiceNames,
}: { selectedServiceNames: Color[]; setSelectedServiceNames: (value: Color[]) => void }) {
  const appRegs = useServerStore((state) => state.appRegs);

  return (
    <ToggleGroup
      type="multiple"
      className="space-x-1.5"
      value={selectedServiceNames}
      onValueChange={(value: Color[]) => setSelectedServiceNames(value)}>
      <ToggleGroupItem
        disabled={appRegs?.currentServiceName === 'blue'}
        value="blue"
        aria-label="blue"
        className="font-bold">
        🔵 Blue
      </ToggleGroupItem>
      <ToggleGroupItem
        disabled={appRegs?.currentServiceName === 'red'}
        value="red"
        aria-label="red"
        className="font-bold">
        🔴 Red
      </ToggleGroupItem>
      <ToggleGroupItem
        disabled={appRegs?.currentServiceName === 'yellow'}
        value="yellow"
        aria-label="yellow"
        className="font-bold">
        🟡 Yellow
      </ToggleGroupItem>
    </ToggleGroup>
  );
}
