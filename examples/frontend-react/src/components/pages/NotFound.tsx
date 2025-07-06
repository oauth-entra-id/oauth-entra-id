import { Navigate } from 'react-router';

export function NotFound() {
  return <Navigate to="/login" replace />;
}
