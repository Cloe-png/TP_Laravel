<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Utilisateur;
use App\Models\Log;
use App\Models\Reactivation;
use App\Http\Controllers\Email;
use PragmaRX\Google2FA\Google2FA;

/* A FAIRE (fiche 3, partie 2, question 1) : inclure ci-dessous le use PHP pour la libriairie gérant l'A2F */

// A FAIRE (fiche 3, partie 3, question 4) : inclure ci-dessous le use PHP pour la libriairie gérant le JWT

class Connexion extends Controller
{
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
    public function boutonVerificationCodeA2F() {
        $validationFormulaire = false; // Booléen qui indique si les données du formulaire sont valides
        $messagesErreur = array(); // Tableau contenant les messages d'erreur à afficher

        /* A FAIRE (fiche 3, partie 2, question 1) : vérification du code A2F */

        public function boutonVerificationCodeA2F() {
        $validationFormulaire = false; // Indique si le code est valide
        $messagesErreur = array();    // Messages d'erreur à afficher

        // Récupération de l'utilisateur connecté
        $utilisateurId = session()->get('connexion');
        $utilisateur = Utilisateur::find($utilisateurId);

        if (!$utilisateur) {
            $messagesErreur[] = "Utilisateur introuvable.";
        } else {
            // Initialisation de Google2FA
            $google2fa = new Google2FA();

            // Récupération du code soumis par l'utilisateur
            $codeA2F = $_POST['code_a2f'] ?? null;

            if (!$codeA2F) {
                $messagesErreur[] = "Veuillez entrer le code de vérification.";
            } else {
                // Vérification du code avec la clé secrète stockée
                $secretKey = $utilisateur->secretA2F; // Clé secrète liée à l'utilisateur
                $isValid = $google2fa->verifyKey($secretKey, $codeA2F);

                if ($isValid) {
                    // Validation réussie
                    $validationFormulaire = true;
                    session()->forget('connexion'); // Supprime la session
                } else {
                    // Code incorrect
                    $messagesErreur[] = "Code incorrect. Veuillez réessayer.";
                }
            }
        }

        if ($validationFormulaire) {
            // Redirection vers la page de profil après validation réussie
            return redirect()->to('profil')->send();
        } else {
            // Retourne la vue avec les erreurs
            return view('formulaireA2F', ["messagesErreur" => $messagesErreur]);
        }
    }
}

        /* A FAIRE (fiche 3, partie 3, question 4) : générer un JWT une fois le code A2F validé + création du cookie + redirection vers la page de profil */

        // Redirection vers la page du profil :
        //return redirect()->to('profil')->send();
    }
    
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
