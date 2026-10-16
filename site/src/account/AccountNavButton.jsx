import { requestSignIn, useSession } from "../api/session.js";
import Avatar from "./Avatar.jsx";

export default function AccountNavButton({ onOpenAccount }) {
  const { status, user } = useSession();
  if (status === "unknown") return null;
  if (status !== "signed_in") {
    return <button type="button" className="ghost top-nav-account-btn" onClick={requestSignIn}>Sign in</button>;
  }
  const name = user.display_name || user.email;
  return (
    <button type="button" className="ghost top-nav-account-btn" onClick={onOpenAccount} title={user.email}>
      <Avatar className="top-nav-avatar" url={user.avatar_url} name={name} />
      <span className="top-nav-account-name">{name}</span>
    </button>
  );
}
