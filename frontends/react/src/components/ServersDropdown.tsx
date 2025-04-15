import { ChevronDown } from 'lucide-react';
import { serversMap, useServerStore } from '~/stores/serverStore';
import { Button } from './ui/Button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/DropdownMenu';

export function ServersDropdown() {
  const { setServer, server, label } = useServerStore();
  const CurrentServerIcon = serversMap[server].Icon;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="sm" variant="outline">
          <div className="flex items-center justify-between">
            <CurrentServerIcon />
            <span className="text-sm mx-2">{label}</span>
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
  );
}
