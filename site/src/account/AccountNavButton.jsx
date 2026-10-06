import { requestSignIn, useSession } from "../api/session.js";

export default function AccountNavButton({ onOpenAccount }) {
  const { status, user } = useSession();
  if (status === "unknown") return null;
  if (status !== "signed_in") {
    return <button type="button" className="ghost top-nav-account-btn" onClick={requestSignIn}>Sign in</button>;
  }
  const name = user.display_name || user.email;
  return (
    <button type="button" className="ghost top-nav-account-btn" onClick={onOpenAccount} title={user.email}>
      {user.avatar_url
        ? <img className="top-nav-avatar" src={user.avatar_url} alt="" referrerPolicy="no-referrer" />
        : <span className="top-nav-avatar top-nav-avatar-initial" aria-hidden="true">{name[0].toUpperCase()}</span>}
      <span className="top-nav-account-name">{name}</span>
    </button>
  );
}
