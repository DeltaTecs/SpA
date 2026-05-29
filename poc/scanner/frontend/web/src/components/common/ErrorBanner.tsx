export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="state state--error" role="alert">
      <strong>Something went wrong.</strong>
      <div className="state__detail">{message}</div>
    </div>
  );
}
