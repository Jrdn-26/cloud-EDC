import logging
import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)


def domaine_accepte_emails(email: str) -> bool:
    try:
        domaine = email.split('@')[-1].lower().strip()
        if not domaine:
            return False
        answers = dns.resolver.resolve(domaine, 'MX', lifetime=5)
        return len(answers) > 0
    except dns.resolver.NXDOMAIN:
        logger.info(f"Domaine inexistant : {email}")
        return False
    except dns.resolver.NoAnswer:
        try:
            dns.resolver.resolve(domaine, 'A', lifetime=5)
            return True
        except Exception:
            return False
    except Exception as e:
        logger.warning(f"Vérif DNS impossible pour {email} : {e}")
        return True
