import { useForm } from '@tanstack/react-form';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Navigate } from 'react-router';
import { toast } from 'sonner';
import { AppInfo } from '~/components/AppInfo';
import { GitHubLink } from '~/components/GitHubLink';
import { Microsoft } from '~/components/icons/Microsoft';
import { ServersDropdown } from '~/components/ServersDropdown';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '~/components/ui/Card';
import { Input } from '~/components/ui/Input';
import { Label } from '~/components/ui/Label';
import { Switch } from '~/components/ui/Switch';
import { MutedText, Title } from '~/components/ui/Text';
import { ToggleGroup, ToggleGroupItem } from '~/components/ui/ToggleGroup';
import { cn } from '~/lib/utils';
import { zEmailForm } from '~/lib/zod';
import { getAuthUrl } from '~/services/user';
import { useServerStore } from '~/stores/server-store';
import { useUserStore } from '~/stores/user-store';

export default function Login() {
  const queryClient = useQueryClient();
  const [ssoEnabled, setSsoEnabled] = useState(true);
  const [currentNumber, setCurrentNumber] = useState<'1' | '2'>('1');
  const user = useUserStore((state) => state.user);
  const appInfo = useServerStore((state) => state.appInfo);
  const loginUser = useMutation({
    mutationFn: getAuthUrl,
    onSuccess: async (url) => {
      window.location.href = url;
      await queryClient.invalidateQueries({ queryKey: ['user'] });
    },
    onError: () => {
      toast.error('Could not login', { duration: 1000 });
    },
  });
  const form = useForm({
    defaultValues: { email: '' },
    validators: { onChange: zEmailForm },
    onSubmit: async ({ value }) =>
      await loginUser.mutateAsync({ email: value.email, azureId: appInfo?.currentServiceIds[currentNumber] }),
  });

  if (user) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="flex flex-col items-center justify-center mt-2">
      <div className="flex flex-col items-center justify-center space-y-3 z-10">
        <Title>
          Welcome,
          <br /> Guest
        </Title>
        <AppInfo />
        <Card>
          <CardHeader>
            <CardTitle>Login into account</CardTitle>
            <CardDescription>Enter your email below to login</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <form.Field name="email">
              {(field) => (
                <>
                  <Label className="sr-only" htmlFor={field.name}>
                    Email
                  </Label>
                  <Input
                    type="email"
                    name={field.name}
                    id={field.name}
                    value={field.state.value}
                    onChange={(e) => field.handleChange(e.target.value)}
                    onBlur={field.handleBlur}
                    placeholder="nickname@email.com"
                    autoCorrect="off"
                    autoCapitalize="none"
                    autoComplete="email"
                  />
                </>
              )}
            </form.Field>
            <form.Subscribe>
              {({ canSubmit, isDirty, isSubmitting }) => (
                <Button className="w-full" disabled={!(canSubmit && isDirty)} onClick={() => form.handleSubmit()}>
                  {isSubmitting ? 'Submitting...' : 'Sign In with Email'}
                </Button>
              )}
            </form.Subscribe>
            <OrContinueWith />
            <Button
              variant="outline"
              className="w-full"
              onClick={() =>
                loginUser.mutate({
                  loginPrompt: ssoEnabled ? undefined : 'select-account',
                  azureId: appInfo?.currentServiceIds[currentNumber],
                })
              }>
              <Microsoft /> Microsoft
            </Button>
            <div className="flex items-center justify-center mt-2">
              <Switch id="sso" checked={ssoEnabled} onCheckedChange={setSsoEnabled} />
              <Label
                htmlFor="sso"
                className={cn('text-sm mx-2', ssoEnabled ? 'text-foreground' : 'text-muted-foreground')}>
                Single Sign-On
              </Label>
            </div>
          </CardContent>
        </Card>
        <div className="flex items-center gap-2">
          <ServersDropdown />{' '}
          <ToggleGroup
            type="single"
            size="sm"
            className="gap-[-10px] border-[1.5px] rounded-lg bg-background"
            value={currentNumber}
            onValueChange={(value) => setCurrentNumber(value as '1' | '2')}>
            <ToggleGroupItem
              value="1"
              size="sm"
              className={cn(
                currentNumber === '1' && 'data-[state=on]:bg-primary data-[state=on]:text-primary-foreground',
              )}>
              1
            </ToggleGroupItem>
            <ToggleGroupItem
              value="2"
              size="sm"
              className={cn(
                currentNumber === '2' && 'data-[state=on]:bg-primary data-[state=on]:text-primary-foreground',
              )}>
              2
            </ToggleGroupItem>
          </ToggleGroup>
        </div>
        <MutedText>React demo that shows how to integrate OAuth2.0 Flow.</MutedText>
        <GitHubLink />
      </div>
    </div>
  );
}

function OrContinueWith() {
  return (
    <div className="relative my-4">
      <div className="absolute inset-0 flex items-center">
        <span className="w-full border-t" />
      </div>
      <div className="relative flex justify-center text-xs uppercase">
        <span className="px-2 bg-background text-muted-foreground">Or continue with</span>
      </div>
    </div>
  );
}
