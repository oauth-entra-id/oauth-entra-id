import { useForm } from '@tanstack/react-form';
import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { z } from 'zod';
import { Microsoft } from '~/components/icons/Microsoft';
import { Button } from '~/components/ui/Button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '~/components/ui/Card';
import { Input } from '~/components/ui/Input';
import { Label } from '~/components/ui/Label';
import { Switch } from '~/components/ui/Switch';
import { cn } from '~/lib/utils';
import { getAuthUrl } from '~/services/user';

export const Route = createFileRoute('/login')({
  component: Login,
});

function Login() {
  const [ssoEnabled, setSsoEnabled] = useState(true);

  const loginUser = async (email?: string) => {
    const url = await getAuthUrl({ email, loginPrompt: !ssoEnabled ? 'select-account' : undefined });
    if (url) window.location.href = url;
  };

  const form = useForm({
    defaultValues: {
      email: '',
    },
    validators: {
      onChange: z.object({ email: z.string().trim().email().min(1).max(128) }),
    },
    onSubmit: async ({ value }) => {
      loginUser(value.email);
    },
  });

  return (
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
                placeholder="name@work.com"
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
        <Button variant="outline" className="w-full" onClick={async () => await loginUser()}>
          <Microsoft /> Microsoft
        </Button>
        <div className="flex items-center justify-center mt-2">
          <Switch id="sso" checked={ssoEnabled} onCheckedChange={setSsoEnabled} />
          <Label htmlFor="sso" className={cn('text-sm mx-2', ssoEnabled ? 'text-foreground' : 'text-muted-foreground')}>
            Single Sign-On
          </Label>
        </div>
      </CardContent>
    </Card>
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
