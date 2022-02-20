
import java.net.*;
import java.io.*;

public class SocketServidor
{    
    public static void main (String [] args)
    {

        String linealeida;
        String lineaescrita;
        boolean bandera=false;
        
        //new SocketServidor();
        if(args.length != 1){
        	System.err.println(
        		"Uso desde la consola: java SocketServidor <numero de puerto>");
        	System.exit(1);
        }
        
        int numeroPuerto = Integer.parseInt(args[0]);
        System.out.println("Servidor en línea esperando por un cliente...");
        //while(){
		try(ServerSocket socketdelServidor = new ServerSocket(Integer.parseInt(args[0]))){
			do{
				Socket socketdelCliente = socketdelServidor.accept();
				if(bandera==false){
					System.out.println("Se ha conectado un cliente wiii");
				}
				PrintWriter escritor = new PrintWriter(socketdelCliente.getOutputStream(),true);
				BufferedReader lector = new BufferedReader(new InputStreamReader(socketdelCliente.getInputStream()));
				
				if(bandera==false){
					escritor.println("Te has conectado al servidor");
					bandera=true;
				}else{
					escritor.println("Recibido, cambio");
				}
				
				linealeida= lector.readLine();
				if(linealeida != null){
					System.out.println("El Eco del cliente dice: " + linealeida);
					//escritor.println("Recibido, cambio");
					if(linealeida.startsWith("Adios.")){
						break;
					}
				}
				
				
			}while(!linealeida.equals("Adios."));
		} catch(IOException e){
			System.out.println(" ocurrio una excepcion al intentar escuchar " + numeroPuerto + " o esperando por una conexion");
			System.out.println(e.getMessage());
		}
		
		//socketdelServidor.close();
        //}
    }
    
}
