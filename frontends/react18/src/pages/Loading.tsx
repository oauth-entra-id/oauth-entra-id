import { FaSpinner } from 'react-icons/fa';

export default function Loading() {
  return (
    <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-background text-foreground">
      <FaSpinner className="animate-spin text-4xl text-primary mb-4" />
      <div className="text-2xl font-semibold">Please wait...</div>
      <div className="text-sm text-muted-foreground mt-2">Loading, this might take a few seconds.</div>
    </div>
  );
}
