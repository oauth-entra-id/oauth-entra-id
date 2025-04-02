import { createFileRoute } from '@tanstack/react-router';
import { ChevronDown } from 'lucide-react';
import { Express } from '~/components/icons/Express';
import { Fastify } from '~/components/icons/Fastify';
import { HonoJS } from '~/components/icons/HonoJS';
import { NestJS } from '~/components/icons/NestJS';
import { Button } from '~/components/ui/Button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '~/components/ui/DropdownMenu';
import { type Server, useServerStore } from '~/stores/serverStore';

export const Route = createFileRoute('/login')({
  component: RouteComponent,
});

const serversMap = {
  express: { Icon: Express, label: 'Express', value: 'express' },
  nestjs: { Icon: NestJS, label: 'NestJS', value: 'nestjs' },
  fastify: { Icon: Fastify, label: 'Fastify', value: 'fastify' },
  honojs: { Icon: HonoJS, label: 'HonoJS', value: 'honojs' },
} as { [key: string]: { Icon: React.FC<React.SVGProps<SVGSVGElement>>; label: string; value: Server } };

function RouteComponent() {
  const { setServer, server } = useServerStore();

  const CurrentServerIcon = serversMap[server]?.Icon || HonoJS;
  const CurrentServerLabel = serversMap[server]?.label || 'HonoJS';

  return (
    <div className="mx-auto mt-4 flex flex-col items-center justify-center max-w-xl space-y-8">
      <h1 className="text-5xl font-bold text-center">
        Welcome, <div>Guest</div>
      </h1>
      <div className="flex flex-col items-center space-y-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button size="sm" variant="outline" className="relative bg-background opacity-85 z-10">
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
      <p className="text-sm text-muted-foreground">
        This demo is supposed to show you how to use Microsoft Entra ID OAuth2.0.
      </p>
    </div>
  );
}
