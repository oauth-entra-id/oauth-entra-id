import { createFileRoute } from '@tanstack/react-router';
import { ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { z } from 'zod';
import { Express } from '~/components/icons/Express';
import { Fastify } from '~/components/icons/Fastify';
import { HonoJS } from '~/components/icons/HonoJS';
import { Microsoft } from '~/components/icons/Microsoft';
import { NestJS } from '~/components/icons/NestJS';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '~/components/ui/Card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '~/components/ui/DropdownMenu';
import { Input } from '~/components/ui/Input';
import { Label } from '~/components/ui/Label';
import { Switch } from '~/components/ui/Switch';
import { MutedText, Title } from '~/components/ui/Text';
import { getAuthUrl } from '~/services/user';
import { type Server, useServerStore } from '~/stores/serverStore';

const serversMap = {
  express: { Icon: Express, label: 'Express', value: 'express' },
  nestjs: { Icon: NestJS, label: 'NestJS', value: 'nestjs' },
  fastify: { Icon: Fastify, label: 'Fastify', value: 'fastify' },
  honojs: { Icon: HonoJS, label: 'HonoJS', value: 'honojs' },
} as { [key: string]: { Icon: React.FC<React.SVGProps<SVGSVGElement>>; label: string; value: Server } };

export const Route = createFileRoute('/login')({
  component: () => {
    const { setServer, server } = useServerStore();

    const CurrentServerIcon = serversMap[server]?.Icon || HonoJS;
    const CurrentServerLabel = serversMap[server]?.label || 'HonoJS';

    const [email, setEmail] = useState('');
    const [isEmailValid, setIsEmailValid] = useState(false);
    const [ssoEnabled, setSsoEnabled] = useState(true);

    function handleOnChange(e: React.ChangeEvent<HTMLInputElement>) {
      setEmail(e.target.value);
      setIsEmailValid(z.string().email().safeParse(e.target.value).success);
    }

    const loginUser = async (email?: string) => {
      if (email && !isEmailValid) return;
      const url = await getAuthUrl({
        email,
        loginPrompt: ssoEnabled ? undefined : 'select-account',
      });
      if (url) {
        window.location.href = url;
      }
    };

    return (
      <div className="flex flex-col items-center justify-center space-y-8">
        <Title>
          Welcome,
          <br /> Guest
        </Title>
        <div className="flex flex-col items-center space-y-2">
          <Card>
            <CardHeader>
              <CardTitle>Login into account</CardTitle>
              <CardDescription>Enter your email below to login</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col space-y-4 w-full">
                <div className="flex flex-col space-y-2 w-full">
                  <Label className="sr-only" htmlFor="email">
                    Email
                  </Label>
                  <Input
                    autoCapitalize="none"
                    autoComplete="email"
                    autoCorrect="off"
                    id="email"
                    onChange={handleOnChange}
                    placeholder="name@work.com"
                    type="email"
                    value={email}
                  />
                  <Button disabled={!isEmailValid} onClick={() => loginUser(email)}>
                    Sign In with Email
                  </Button>
                </div>
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="px-2 bg-background text-muted-foreground">Or continue with</span>
                  </div>
                </div>
                <Button variant="outline" onClick={() => loginUser()}>
                  <Microsoft className="mr-1" /> Microsoft
                </Button>
                <div className="flex items-center justify-center space-x-2">
                  <Switch id="sso" checked={ssoEnabled} onCheckedChange={setSsoEnabled} />
                  <Label
                    htmlFor="sso"
                    className={`text-sm ${ssoEnabled ? 'text-foreground' : 'text-muted-foreground'}`}>
                    Single Sign-On
                  </Label>
                </div>
              </div>
            </CardContent>
          </Card>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button size="sm" variant="outline">
                <div className="flex items-center justify-between">
                  <CurrentServerIcon />
                  <span className="text-sm mx-2">{CurrentServerLabel}</span>
                  <ChevronDown />
                </div>
                <span className="sr-only">Toggle server</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Choose server</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {Object.entries(serversMap).map(([key, { Icon, label, value }]) => (
                <DropdownMenuItem key={key} onClick={() => setServer(value)}>
                  <div className="flex items-center justify-between space-x-2.5">
                    <Icon className="size-4" /> <span className="text-sm">{label}</span>
                  </div>
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        <MutedText>This demo is supposed to show you how to use Microsoft Entra ID OAuth2.0.</MutedText>
      </div>
    );
  },
});
