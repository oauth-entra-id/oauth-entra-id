import { useCallback, useState } from 'react';
import type { IconType } from 'react-icons';
import { FaCaretDown } from 'react-icons/fa6';
import { SiExpress, SiFastify, SiHono, SiNestjs } from 'react-icons/si';
import { z } from 'zod';
import { MicrosoftSVG } from '~/components/MicrosoftIcon';
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
import { getAuthUrl } from '~/services/user';
import { type Server, useServerStore } from '~/stores/serverStore';

export default function Login() {
  return (
    <div className="mx-auto mt-4 flex flex-col items-center justify-center max-w-xl space-y-8">
      <h1 className="text-5xl font-bold text-center">
        Welcome, <div>Guest</div>
      </h1>
      <div className="flex flex-col items-center space-y-2">
        <LoginCard />
        <ChooseServer />
      </div>
      <p className="text-sm text-muted-foreground">
        This demo is supposed to show you how to use Microsoft OAuth2.0 to authenticate users.
      </p>
    </div>
  );
}

export function LoginCard() {
  const [email, setEmail] = useState('');
  const [isEmailValid, setIsEmailValid] = useState(false);
  const [ssoEnabled, setSsoEnabled] = useState(true);

  function handleOnChange(e: React.ChangeEvent<HTMLInputElement>) {
    setEmail(e.target.value);
    setIsEmailValid(z.string().email().safeParse(e.target.value).success);
  }

  const loginUser = useCallback(
    async (email?: string) => {
      if (email && !isEmailValid) return;
      const url = await getAuthUrl({
        email,
        loginPrompt: ssoEnabled ? undefined : 'select-account',
      });
      if (url) {
        window.location.href = url;
      }
    },
    [isEmailValid, ssoEnabled],
  );

  return (
    <Card className="relative z-10">
      <CardHeader className="px-6 pt-6 pb-2">
        <CardTitle className="text-2xl text-center font-semibold tracking-tight">Login into account</CardTitle>
        <CardDescription className="text-sm text-muted-foreground">
          Enter your email below to login into your account
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-1 px-6 pb-6 flex flex-col items-start text-md">
        <div className="flex flex-col space-y-2 text-center" />
        <div className="grid gap-6 w-full">
          <div className="grid gap-2">
            <div className="grid gap-1">
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
            </div>
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
            <MicrosoftSVG className="mr-1" /> Microsoft
          </Button>
          <div className="flex items-center justify-center space-x-2">
            <Switch id="sso" checked={ssoEnabled} onCheckedChange={setSsoEnabled} />
            <Label htmlFor="sso" className={`text-sm ${ssoEnabled ? 'text-foreground' : 'text-muted-foreground'}`}>
              Single Sign-On
            </Label>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

const serversMap = {
  express: { Icon: SiExpress, label: 'Express', value: 'express' },
  nestjs: { Icon: SiNestjs, label: 'NestJS', value: 'nestjs' },
  fastify: { Icon: SiFastify, label: 'Fastify', value: 'fastify' },
  honojs: { Icon: SiHono, label: 'HonoJS', value: 'honojs' },
} as { [key: string]: { Icon: IconType; label: string; value: Server } };

export function ChooseServer() {
  const { setServer, server } = useServerStore();

  const CurrentServerIcon = serversMap[server]?.Icon || SiExpress;
  const CurrentServerLabel = serversMap[server]?.label || 'Express';

  return (
    <div>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="sm" variant="outline" className="relative bg-background opacity-85 z-10">
            <div className="flex items-center justify-between">
              <CurrentServerIcon className="h-5 w-5 mr-2" />
              <span className="text-sm">{CurrentServerLabel}</span>
              <FaCaretDown className="ml-2" />
            </div>
            <span className="sr-only">Toggle server</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>Choose server</DropdownMenuLabel> <DropdownMenuSeparator />
          {Object.entries(serversMap).map(([key, { Icon, label, value }]) => (
            <DropdownMenuItem key={key} onClick={() => setServer(value)}>
              <div className="flex items-center justify-between">
                <Icon className="h-4 w-4 mr-2.5" /> <span className="text-sm">{label}</span>
              </div>
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
