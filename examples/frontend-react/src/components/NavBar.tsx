import { Moon, Sun } from 'lucide-react';
import { Button } from '~/components/ui/Button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '~/components/ui/DropdownMenu';
import { useDevTools } from '~/hooks/useDevTools';
import { useToggle } from '~/hooks/useToggle';
import { useThemeStore } from '~/stores/theme-store';

export function Navbar() {
  const setTheme = useThemeStore((state) => state.setTheme);
  const [devToolsDisabled, toggleDevTools] = useToggle(true);
  useDevTools(devToolsDisabled);

  return (
    <nav className="w-full flex flex-row items-center justify-between px-4 py-2 z-20">
      {/** biome-ignore lint/a11y/noStaticElementInteractions: Undercover */}
      <div
        className="font-mono font-black italic text-xl bg-gradient-to-br from-foreground to-50% to-muted-foreground bg-clip-text text-transparent"
        onDoubleClick={() => toggleDevTools()}>
        React
      </div>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="icon" variant="outline">
            <Sun className="h-[1.2rem] w-[1.2rem] rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
            <Moon className="absolute h-[1.2rem] w-[1.2rem] rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
            <span className="sr-only">Toggle theme</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem
            onClick={() => {
              setTheme('light');
            }}>
            Light
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={() => {
              setTheme('dark');
            }}>
            Dark
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={() => {
              setTheme('system');
            }}>
            System
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </nav>
  );
}
