<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Utilisateur;
use App\Models\Log;
use App\Models\Reactivation;
use App\Http\Controllers\Email;
use PragmaRX\Google2FA\Google2FA;
use Firebase\JWT\JWT;

/* A FAIRE (fiche 3, partie 2, question 1) : inclure ci-dessous le use PHP pour la libriairie gérant l'A2F */

// A FAIRE (fiche 3, partie 3, question 4) : inclure ci-dessous le use PHP pour la libriairie gérant le JWT

class Connexion extends Controller {

    public function afficherFormulaireConnexion() {
        return view('formulaireConnexion', []);
    }

    public function afficherFormulaireVerificationA2F() {
        if(session()->has('connexion')) {
            if(Utilisateur::where("idUtilisateur", session()->get('connexion'))->count() > 0) {
                return view('formulaireA2F', []);
            }
            else {
                session()->forget('connexion');
                return view('formulaireConnexion', []);
            }
        }
        else {
            return view('formulaireConnexion', []);
        }
    }

    public function reactivationCompte() {
        $validation = false; // Booléen vrai/faux si les conditions de vérification sont remplies pour réactiver le compte
        $messageAAfficher = null; // Contient le message d'erreur ou de succès à afficher

        /* A FAIRE (fiche 3, partie 1, question 4) : vérification du code dans l'URL ainsi que de l'expiration du lien + réactivation du compte */

        if($validation === false) {
            return view("pageErreur", ["messageErreur" => $messageAAfficher]);
        }
        else {
            return view('confirmation', ["messageConfirmation" => $messageAAfficher]);
        }
    }
    
    /* A FAIRE (fiche 3, partie 3, question 4) : générer un JWT une fois le code A2F validé + création du cookie + redirection vers la page de profil */
    public function boutonVerificationCodeA2F() {
        $validationFormulaire = false; // Booléen qui indique si les données du formulaire sont valides
        $messagesErreur = array(); // Tableau contenant les messages d'erreur à afficher

        $primaryKey = session()->get('connexion');
        $utilisateur = Utilisateur::find($primaryKey);

        if (!$utilisateur) {
            $messagesErreur[] = "Utilisateur introuvable.";
        } else {
            $google2fa = new Google2FA();
            $codeA2F = $_POST['code_a2f'] ?? null;

            if (!$codeA2F) {
                $messagesErreur[] = "Veuillez entrer le code de vérification.";
            } else {
                $secretKey = $utilisateur->secretA2F;
                $isValid = $google2fa->verifyKey($secretKey, $codeA2F);

                if ($isValid) {
                    $validationFormulaire = true;

                    // Génération du JWT après validation réussie
                    $jwtPayload = [
                        "name" => $utilisateur->email,
                        "sub" => $utilisateur->idUtilisateur,
                        "iat" => time()
                    ];

                    $jwtSecret = "T3mUjGjhC6WuxyNGR2rkUt2uQgrlFUHx";
                    $jwtToken = JWT::encode($jwtPayload, $jwtSecret, 'HS256');

                    // Création du cookie "auth" pour 30 jours
                    setcookie("auth", $jwtToken, time() + (30 * 24 * 60 * 60), "/", "", false, true);

                    // Redirection vers la page de profil
                    return redirect()->to('profil')->send();
                } else {
                    $messagesErreur[] = "Code incorrect. Veuillez réessayer.";
                }
            }
        }

        if (!$validationFormulaire) {
            return view('formulaireA2F', ["messagesErreur" => $messagesErreur]);
        }
    }
        

        // Redirection vers la page du profil :
        //return redirect()->to('profil')->send();
    
    public function boutonConnexion() {
        $validationFormulaire = false; // Booléen qui indique si les données du formulaire sont valides
        $messagesErreur = array(); // Tableau contenant les messages d'erreur à afficher

        /* A FAIRE (fiche 3, partie 1, question 3) : vérification du couple login/mot de passe */
        // Récupération de l'utilisateur à partir de l'email
        $utilisateur = Utilisateur::where('email', $_POST["email"])->first();

        if (!$utilisateur) {
            // Compte introuvable
            $messagesErreur[] = 'Compte introuvable';
        }
        else {
            if ($utilisateur->estDesactiveUtilisateur === 1) {
                $messagesErreur[] = 'Compte désactivé';
            }
            else {
                if (!password_verify($_POST["motdepasse"], $utilisateur->motDePasseUtilisateur)) {
                    // Incrémentation des tentatives échouées
                    $utilisateur->tentativesEchoueesUtilisateur += 1;
                    $utilisateur->save();
        
                    Log::ecrireLog($email, 'Échec : Mot de passe incorrect');
        
                    // Bloquer le compte après 5 tentatives
                    if ($utilisateur->tentativesEchoueesUtilisateur >= 5) {
                        $utilisateur->estDesactiveUtilisateur = '0';
                        $utilisateur->save();
        
                        Recuperation::creerCodeRecuperation($utilisateur);
        
                        $messagesErreur[] = 'Compte bloqué. Un email de réactivation a été envoyé.';
                    }
                    else {
                        $tentativesRestantes = 5 - $utilisateur->tentativesEchoueesUtilisateur;
                        $messagesErreur[] = "Mot de passe incorrect. Tentatives restantes : $tentativesRestantes.";
                    }
                }
                else {
                    $utilisateur->tentativesEchoueesUtilisateur = 0;
                    $utilisateur->save();
                    $validationFormulaire = true;
                    session()->put('connexion', $utilisateur->idUtilisateur);
                    Log::ecrireLog($email, 'Succès : Authentification réussie');
                }
            }
        }

        if($validationFormulaire === false) {
            return view('formulaireConnexion', ["messagesErreur" => $messagesErreur]);
        }
        else {
            return view('formulaireA2F', []);
        }
    }

    public function deconnexion() {
        if(session()->has('connexion')) {
            session()->forget('connexion');
        }
        if(isset($_COOKIE["auth"])) {
            setcookie("auth", "", time()-3600);
        }

        return redirect()->to('connexion')->send();
    }

    public function validationFormulaire() {
        if(isset($_POST["boutonVerificationCodeA2F"])) {
            return $this->boutonVerificationCodeA2F();
        }
        else {
            if(isset($_POST["boutonConnexion"])) {
                return $this->boutonConnexion();
            }
            else {
                return redirect()->to('connexion')->send();
            }
        }
    }
}
