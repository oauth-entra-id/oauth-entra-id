import { useMutation, useQueryClient } from '@tanstack/react-query';
import { createFileRoute } from '@tanstack/react-router';
import { LogOut } from 'lucide-react';
import { useState } from 'react';
import Confetti from 'react-confetti';
import { toast } from 'sonner';
import { AppInfo } from '~/components/AppInfo';
import { GitHubLink } from '~/components/GitHubLink';
import { ServersDropdown } from '~/components/ServersDropdown';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '~/components/ui/Card';
import { Separator } from '~/components/ui/Separator';
import { Title } from '~/components/ui/Text';
import { ToggleGroup, ToggleGroupItem } from '~/components/ui/ToggleGroup';
import { useWindowDimensions } from '~/hooks/useWindowDimensions';
import { getTokensOnBehalfOf, logoutAndGetLogoutUrl } from '~/services/user';
import { type Color, type Server, serversMap, useServerStore } from '~/stores/server-store';
import { useUserStore } from '~/stores/user-store';

export const Route = createFileRoute('/(protected)/')({
  component: Home,
});

function Home() {
  const queryClient = useQueryClient();
  const { width, height } = useWindowDimensions();
  const { user, setUser } = useUserStore();
  const { mutate: handleLogout } = useMutation({
    mutationFn: logoutAndGetLogoutUrl,
    onSuccess: async (url) => {
      await queryClient.invalidateQueries({ queryKey: ['user'] });
      window.open(url, '_blank');
      setUser(null);
    },
    onError: () => {
      toast.error('Could not logout', { duration: 1000 });
    },
  });

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
              <div>
                <span className="font-bold">Injected Data:</span>{' '}
                {user.injectedData ? `${user.injectedData.randomNumber} (Random Number)` : 'None'}
              </div>
              <Separator />
              <div className="flex flex-col items-start justify-center my-2 px-1 text-sm font-semibold">
                On-Behalf-Of Flow:
                <OnBehalfOf />
              </div>
              <Separator />
              <div className="flex flex-col items-start justify-center my-2 px-1 text-sm font-semibold">
                Get B2B Data:
                <GetB2BData />
              </div>
            </CardContent>
            <CardFooter className="flex flex-col items-center justify-center space-y-2">
              <Button variant="destructive" className="w-full" onClick={() => handleLogout()}>
                Logout <LogOut />
              </Button>
            </CardFooter>
          </Card>
          <ServersDropdown />
          <GitHubLink />
        </div>
      </div>

      <div className="absolute inset-0 -z-10 pointer-events-none">
        <Confetti width={width} height={height} numberOfPieces={200} recycle={false} gravity={1} friction={0.95} />
      </div>
    </>
  );
}

function OnBehalfOf() {
  const [selectedOnBehalfOf, setSelectedOnBehalfOf] = useState<Color[]>([]);
  const appInfo = useServerStore((state) => state.appInfo);
  const { mutate: handleOnBehalfOf } = useMutation({
    mutationFn: () => getTokensOnBehalfOf(selectedOnBehalfOf),
    onSuccess: (tokensSet) => {
      setSelectedOnBehalfOf([]);
      toast.success(tokensSet === 1 ? 'New token created!' : `${tokensSet} new tokens created!`, { duration: 1000 });
    },
    onError: () => {
      setSelectedOnBehalfOf([]);
      toast.error('Could not create new tokens', { duration: 1000 });
    },
  });

  return (
    <div className="flex w-full justify-between items-center px-1.5 mb-1">
      <ToggleGroup
        type="multiple"
        className="space-x-1.5"
        value={selectedOnBehalfOf}
        onValueChange={(value: Color[]) => setSelectedOnBehalfOf(value)}>
        <ToggleGroupItem
          disabled={appInfo?.currentServiceName === 'blue'}
          value="blue"
          aria-label="blue"
          size="sm"
          className="text-[0.0.75rem]">
          🔵 Blue
        </ToggleGroupItem>
        <ToggleGroupItem
          disabled={appInfo?.currentServiceName === 'red'}
          value="red"
          aria-label="red"
          size="sm"
          className="text-[0.0.75rem]">
          🔴 Red
        </ToggleGroupItem>
        <ToggleGroupItem
          disabled={appInfo?.currentServiceName === 'yellow'}
          value="yellow"
          aria-label="yellow"
          size="sm"
          className="text-[0.0.75rem]">
          🟡 Yellow
        </ToggleGroupItem>
      </ToggleGroup>
      <div className="flex-1 ml-2 max-w-32">
        <Button
          size="sm"
          variant="outline"
          className="text-sm font-semibold w-full"
          disabled={selectedOnBehalfOf.length === 0}
          onClick={() => handleOnBehalfOf()}>
          Get Tokens
        </Button>
      </div>
    </div>
  );
}

function GetB2BData() {
  const [selectedService, setSelectedService] = useState<Server | undefined>();
  const server = useServerStore((state) => state.server);
  return (
    <div className="flex w-full justify-between items-center px-1.5 mb-1">
      <ToggleGroup
        type="single"
        className="space-x-1.5"
        value={selectedService}
        onValueChange={(value: Server) => setSelectedService(value)}>
        {Object.entries(serversMap).map(
          ([key, { Icon, label, value }]) =>
            server !== value && (
              <ToggleGroupItem key={key} value={value} aria-label={label} size="sm" className="text-[0.75rem]">
                <Icon />
                {label}
              </ToggleGroupItem>
            ),
        )}
      </ToggleGroup>
      <div className="flex-1 ml-2 max-w-32">
        <Button variant="outline" size="sm" className="text-sm font-semibold w-full">
          Get Data
        </Button>
      </div>
    </div>
  );
}
