<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

use App\Models\Utilisateur;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Authentification
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // On vérifie la présence du cookie d'authentification
		if(isset($_COOKIE["auth"])) {
			// Tentative de déchiffrement du cookie de connexion
			try {
				// Récupération des infos du JWT contenus dans le cookie.
				$cle = "T3mUjGjhC6WuxyNGR2rkUt2uQgrlFUHx";
				$jwt = JWT::decode($_COOKIE["auth"], new Key($cle, 'HS256'));
				$infosAuth = (array) $jwt;
				// Vérification de l'existance du compte utilisateur à partir de l'ID de l'utilisateur contenu dans le JWT
				if(Utilisateur::where("idUtilisateur", $infosAuth["sub"])->count() > 0) {
					return $next($request);
				}
				else {
					// Si l'utilisateur n'existe plus : on détruit le cookie d'authentification et retour à la page de connexion
					setcookie("auth", "", time()-3600);
					return redirect()->to('connexion')->send();
				}
			}
			catch(Exception $ex) {
				// Si le déchiffrement est un échec alors c'est que le cookie est malformé, on détruit le cookie et on renvoie vers la page de connexion
				setcookie("auth", "", time()-3600);
				return redirect()->to('connexion')->send();
			}
		}
		else {
			// Redirection vers la page de connexion :
            return redirect()->to('connexion')->send();
		}
    }
	
	<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

use App\Models\Utilisateur;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Mail;

class Authentification
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Vérifier la présence du cookie d'authentification
        if (isset($_COOKIE["auth"])) {
            try {
                // Tentative de déchiffrement du JWT contenu dans le cookie
                $cle = "T3mUjGjhC6WuxyNGR2rkUt2uQgrlFUHx";
                $jwt = JWT::decode($_COOKIE["auth"], new Key($cle, 'HS256'));
                $infosAuth = (array) $jwt;

                // Vérification de l'existence de l'utilisateur
                if (Utilisateur::where("idUtilisateur", $infosAuth["sub"])->count() > 0) {
                    return $next($request);
                } else {
                    // L'utilisateur n'existe plus, on détruit le cookie et redirige vers la connexion
                    setcookie("auth", "", time() - 3600);
                    return redirect()->to('connexion')->send();
                }
            } catch (\Exception $ex) {
                // Si le déchiffrement échoue, on détruit le cookie et redirige
                setcookie("auth", "", time() - 3600);
                return redirect()->to('connexion')->send();
            }
        } else {
            // Si le cookie est absent, rediriger vers la page de connexion
            return redirect()->to('connexion')->send();
        }
    }


    private function enregistrerLog($email, $message)
    {
        // Log dans un fichier texte
        $logMessage = "[" . date('Y-m-d H:i:s') . "] Email: $email - $message\n";
        file_put_contents(storage_path('logs/auth_logs.txt'), $logMessage, FILE_APPEND);
    }

    private function envoyerEmailReactivation($utilisateur)
    {
        $lienReactivation = "/var/www/html/auth-app/app/Models/Reactivation.php" . base64_encode($utilisateur->email);

        Mail::send([], [], function ($message) use ($utilisateur, $lienReactivation) {
            $message->to($utilisateur->email)
                ->subject('Réactivation de votre compte')
                ->setBody("Bonjour,<br>Votre compte a été désactivé après plusieurs tentatives échouées. Cliquez sur ce lien pour réactiver votre compte : <a href='$lienReactivation'>Réactiver mon compte</a>", 'text/html');
        });
    }
	
}
}