package com.ets.server;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Cette classe permet la reception d'un paquet UDP sur le port de reception
 * UDP/DNS. Elle analyse le paquet et extrait le hostname
 * 
 * Il s'agit d'un Thread qui ecoute en permanance pour ne pas affecter le
 * deroulement du programme
 * 
 * @author Max
 *
 */

public class UDPReceiver extends Thread {
	/**
	 * Les champs d'un Packet UDP 
	 * --------------------------
	 * En-tete (12 octects) 
	 * Question : l'adresse demande 
	 * Reponse : l'adresse IP
	 * Autorite :
	 * info sur le serveur d'autorite 
	 * Additionnel : information supplementaire
	 */

	/**
	 * Definition de l'En-tete d'un Packet UDP
	 * --------------------------------------- 
	 * Identifiant Parametres 
	 * QDcount
	 * Ancount
	 * NScount 
	 * ARcount
	 * 
	 * L'identifiant est un entier permettant d'identifier la requete. 
	 * parametres contient les champs suivant : 
	 * 		QR (1 bit) : indique si le message est une question (0) ou une reponse (1). 
	 * 		OPCODE (4 bits) : type de la requete (0000 pour une requete simple). 
	 * 		AA (1 bit) : le serveur qui a fourni la reponse a-t-il autorite sur le domaine? 
	 * 		TC (1 bit) : indique si le message est tronque.
	 *		RD (1 bit) : demande d'une requete recursive. 
	 * 		RA (1 bit) : indique que le serveur peut faire une demande recursive. 
	 *		UNUSED, AD, CD (1 bit chacun) : non utilises. 
	 * 		RCODE (4 bits) : code de retour.
	 *                       0 : OK, 1 : erreur sur le format de la requete,
	 *                       2: probleme du serveur, 3 : nom de domaine non trouve (valide seulement si AA), 
	 *                       4 : requete non supportee, 5 : le serveur refuse de repondre (raisons de s�ecurite ou autres).
	 * QDCount : nombre de questions. 
	 * ANCount, NSCount, ARCount : nombre d�entrees dans les champs �Reponse�, Autorite,  Additionnel.
	 */

	protected final static int BUF_SIZE = 1024;
	protected String SERVER_DNS = null;//serveur de redirection (ip)
	protected int portRedirect = 53; // port  de redirection (par defaut)
	protected int port; // port de r�ception
	private String adrIP = null; //bind ip d'ecoute
	private String DomainName = "none";
	private String DNSFile = null;
	private boolean RedirectionSeulement = false;
	
	private class ClientInfo { //quick container
		public String client_ip = null;
		public int client_port = 0;
	};
	private HashMap<Integer, ClientInfo> Clients = new HashMap<Integer, ClientInfo>();
	
	private boolean stop = false;

	
	public UDPReceiver() {
	}

	public UDPReceiver(String SERVER_DNS, int Port) {
		this.SERVER_DNS = SERVER_DNS;
		this.port = Port;
	}
	
	
	public void setport(int p) {
		this.port = p;
	}

	public void setRedirectionSeulement(boolean b) {
		this.RedirectionSeulement = b;
	}

	public String gethostNameFromPacket() {
		return DomainName;
	}

	public String getAdrIP() {
		return adrIP;
	}

	private void setAdrIP(String ip) {
		adrIP = ip;
	}

	public String getSERVER_DNS() {
		return SERVER_DNS;
	}

	public void setSERVER_DNS(String server_dns) {
		this.SERVER_DNS = server_dns;
	}

	/*
	 * Méthode pour rediriger vers un autre Server DNS
	 */
	public void redirectionRequete(UDPSender nouvelleRequete, DatagramSocket socket, DatagramPacket packet) throws IOException{

		//On set l'adresse du server nouveau server DNS
		nouvelleRequete.setDest_ip(SERVER_DNS);
		nouvelleRequete.setDest_port(port);
		nouvelleRequete.setSendSocket(socket);
		nouvelleRequete.SendPacketNow(packet);

	}


	public void setDNSFile(String filename) {
		DNSFile = filename;
	}

	public void run() {
		try {

            DatagramSocket serveur = new DatagramSocket(this.port); // *Creation d'un socket UDP


            QueryFinder queryFinder = new QueryFinder(DNSFile);

            UDPSender udpSender = new UDPSender();

			// *Boucle infinie de recpetion
			while (!this.stop) {

				byte[] buff = new byte[0xFF];
				DatagramPacket paquetRecu = new DatagramPacket(buff,buff.length);
				//System.out.println("Serveur DNS  "+serveur.getLocalAddress()+"  en attente sur le port: "+ serveur.getLocalPort());
                System.out.println("Serveur DNS  "+this.SERVER_DNS+"  en attente sur le port: "+ serveur.getLocalPort());

				// *Reception d'un paquet UDP via le socket
				serveur.receive(paquetRecu);

				System.out.println("paquet recu du  "+paquetRecu.getAddress()+"  du port: "+ paquetRecu.getPort());


				// *Creation d'un DataInputStream ou ByteArrayInputStream pour
				// manipuler les bytes du paquet

				ByteArrayInputStream TabInputStream = new ByteArrayInputStream (paquetRecu.getData());


                //We read the request id from the 2 first bytes
                int requestId=0;
                requestId+=TabInputStream.read();
                requestId+=TabInputStream.read();

                //We read the request type
                int requestType;

                //We read the next byte
                byte byteTmp = (byte) TabInputStream.read();
                //we convert the byte to a string that contains 8 chars
                String byteString = String.format("%8s",Integer.toBinaryString(byteTmp & 0xFF)).replace(' ', '0');

                //We check if the first bit of the byte is a 0 or a 1
                if(byteString.charAt(0) == '0'){
                    requestType = 0;
                    System.out.println("\n---- Request ----");
                }
                else{
                    requestType = 1;
                    System.out.println("\n---- Answer ----");
                }



                if(requestType == 0){

                    // ****** Dans le cas d'un paquet requete *****

                    // *Lecture du Query Domain name, a partir du 13 byte


                    //we skipped the 9 next bytes to reach the QUESTION Part
                    TabInputStream.skip(9);

                    String domainName = getDomainName(TabInputStream);

                    System.out.println("Le nom de domaine: "+domainName);

                    // *Sauvegarde du Query Domain name

                    // *Sauvegarde de l'adresse, du port et de l'identifiant de la requete
                    InetAddress requesterIP = paquetRecu.getAddress();
                    int requesterPort = paquetRecu.getPort();

                    // *Si le mode est redirection seulement
                    // *Rediriger le paquet vers le serveur DNS
                    // *Sinon
                    // *Rechercher l'adresse IP associe au Query Domain name
                    // dans le fichier de correspondance de ce serveur

                    // *Si la correspondance n'est pas trouvee
                    // *Rediriger le paquet vers le serveur DNS
                    // *Sinon
                    // *Creer le paquet de reponse a l'aide du UDPAnswerPaquetCreator
                    // *Placer ce paquet dans le socket
                    // *Envoyer le paquet

                    if (this.RedirectionSeulement){
                        //Rediction vers un autre sserveur DNS
                        redirectionRequete(udpSender,serveur,paquetRecu);
                    }
                    else{
                        List<String> domainIpList = queryFinder.StartResearch(domainName);

                        if(domainIpList.size()==0){
                            //we redirect to another DNS server
                            System.out.println("On redirige vers google dns !!");
                        }
                        else{
                            byte[] newAnswerData = UDPAnswerPacketCreator.getInstance().CreateAnswerPacket(paquetRecu.getData(),domainIpList);
                            DatagramPacket answer = new DatagramPacket(newAnswerData,newAnswerData.length,requesterIP,requesterPort);
                            serveur.send(answer);
                        }
                    }
                }
                else{

                // ****** Dans le cas d'un paquet reponse *****
                    // *Lecture du Query Domain name, a partir du 13 byte

                    // *Passe par dessus Type et Class

                    // *Passe par dessus les premiers champs du ressource record
                    // pour arriver au ressource data qui contient l'adresse IP associe
                    //  au hostname (dans le fond saut de 16 bytes)

                    // *Capture de ou des adresse(s) IP (ANCOUNT est le nombre
                    // de r�ponses retourn�es)

                    // *Ajouter la ou les correspondance(s) dans le fichier DNS
                    // si elles ne y sont pas deja

                    // *Faire parvenir le paquet reponse au demandeur original,
                    // ayant emis une requete avec cet identifiant
                    // *Placer ce paquet dans le socket
                    // *Envoyer le paquet

                    TabInputStream.skip(12);

                    List<String> IPList = getIpAddressFromANCOUNT(TabInputStream);

                }

                System.out.println("---- END ----\n\n");


			}
//			serveur.close(); //closing server
		} catch (Exception e) {
			System.err.println("Probl�me � l'ex�cution :");
			e.printStackTrace(System.err);
		}
	}

    /**
     * Method that return the domain name. It needs to be call when the ByteArrayInputStream is at the index 12.
     * @param TabInputStream
     * @return a string that contain the domain name extracted from the request
     */
    private String getDomainName(ByteArrayInputStream TabInputStream){

        //We read the next byte, this numbers correspond to the next numbers of bytes that need to be read
        int byteValue=TabInputStream.read();

        //We store in the domainName from the request
        String domainName = "";

        //The char that match with the value of the current byte
        char[]currentChart = null;

        while(true){

            /*
             *   We check if we need to read chars
             */
            if(byteValue!=0){

                /**
                 * We read the number of chars asked
                 */
                for (int i = 0; i < byteValue; i++) {
                    currentChart = Character.toChars(TabInputStream.read());
                    domainName+=currentChart[0];
                }

                //Then we check if we still need to read other chars
                byteValue = TabInputStream.read();


                if(byteValue>0){
                                /*
                                * If it's yes we add a dot between the first part of
                                * the domain name and the one who arrived
                                */
                    domainName+=".";
                }
                else{
                    break;
                }


            }
        }

        return domainName;
    }

    /**
     * Method that return the list of IP address that have been resolved for the given domain name.
     * The method has to be called than the current byte of the ByteArrayInputStream read is 15
     * @param TabInputStream
     * @return  The list of IP Address
     */
    private List<String> getIpAddressFromANCOUNT(ByteArrayInputStream TabInputStream){

        List<String> ipAddress = new ArrayList<String>();

        //We read the next byte, this numbers correspond to the numbers of IP that need to be extracted
        int nbIpAddress=TabInputStream.read();

        //we store the current IP address from the request
        String currentIpAddress = "";


        for (int i=1; i < 4*nbIpAddress+1; i++){

            int tmp = TabInputStream.read();

            if(i%4 == 0) {
               tmp = TabInputStream.read();
               currentIpAddress+= Integer.toString(tmp);
               ipAddress.add(currentIpAddress);
               currentIpAddress="";
            }
            else {
                tmp = TabInputStream.read();
                currentIpAddress+= Integer.toString(tmp);
                currentIpAddress+=".";
            }

        }

        return ipAddress;

    }



}
