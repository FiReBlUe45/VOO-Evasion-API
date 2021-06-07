from evasion import manageVerbose, channelToCommand, send_cmd
BOX = "192.168.0.15"

def main():
    while True:
        try:
            cmd = input("Entrer un numéro de chaîne : ")
        except:
            exit(0)

        try:
            ch = int(cmd)
            # On fait taire les fonctions exécutées
            with manageVerbose(verbose=False):
                # On génère une liste de commandes
                cmd_ls = channelToCommand(ch)
                print(cmd_ls)
                # On envoie la liste de commandes et on récupère le succès de l'envoie
                r,_ = send_cmd(BOX, 38520, cmd_ls)
            print("Envoie réussi" if r else "Envoie échoué")
        except:
            raise NameError('Le numéro de chaîne doit-être un entier')

if __name__ == "__main__":
    main()
