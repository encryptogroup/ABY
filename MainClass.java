package test;

import java.util.Scanner;
import java.util.regex.*;
import ABY_examples.mill_jni;
import ABY_examples.euc_dist;
import ABY_examples.min_euc_dist;

public class MainClass {
    private static int secpram = 128;
    private static int port = 7766;
    private static int bitlen = 32;
    private static String addr = "127.0.0.1";
    private static final Pattern PATTERN = Pattern.compile(
                    "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|"
                    + "2[0-4]\\d|25[0-5])$");
	private static Scanner reader;
	private static Scanner reader2;
    
    public static void setparams(boolean RD) {
        reader = new Scanner(System.in);
        do {
            try {
                System.out.println("Enter ipaddress for client and server"
                        + " to connect");
                addr = reader.nextLine();
                System.out.println("Enter port number to create socket on");
                String prt = reader.nextLine();
                System.out.println("Enter bitlen 8, 16, 32 or 64");
                String btlen = reader.nextLine();
                System.out.println("Enter the security param:default 128\n"
                        + "80-short\n112-mid\n128-long\n192-extra long\n"
                        + "256-xx long");
                String secparm = reader.nextLine();

                if ("".equals(addr.trim())) {
                    addr = "127.0.0.1";
                } else if (!PATTERN.matcher(addr).matches()) {
                    System.out.println("Invalid addr");
                    throw new NumberFormatException();
                }
                if (!"".equals(prt.trim())) {
                    port = Integer.parseInt(prt);
                    if (port <= 1024 || port > 65535)
                        throw new NumberFormatException();
                }
                if (!"".equals(btlen.trim())) {
                        bitlen = Integer.parseInt(btlen);
                        if (!(bitlen == 8 || bitlen == 16 || bitlen == 32
                                    || bitlen == 64))
                            throw new NumberFormatException();
                }
                if (!"".equals(secparm.trim())) {
                        secpram = Integer.parseInt(secparm);
                        if (!(secpram == 80 || secpram == 112 || secpram == 128
                                    || secpram == 192 || secpram == 256))
                            throw new NumberFormatException();
                }
                RD = false;
            } catch (NumberFormatException nfe) {
                System.err.println("port, addr, bitlen or secpram incorrect:"
                        + " GO AGAIN!");
            }
        } while (RD);
    }

    public static void main(String [] args) {
        int i;

        reader2 = new Scanner(System.in);
        System.out.println("enter 1, 2, 3 to switch examples");

        i = reader2.nextInt();
        //parameters for examples
        int role, money, x, y, nc, dim;
        boolean RD = true;
        
        switch (i) {
            case 1:
                System.out.println("set role and money value");
                role = reader2.nextInt();
                money = reader2.nextInt();
                mill_jni.run(role, money);
                break;

            case 2:
                System.out.println("set role, x and y co-ordinates");
                role = reader2.nextInt();
                x = reader2.nextInt();
                y = reader2.nextInt();
                setparams(RD);
                euc_dist.run(role, x, y, secpram, bitlen, addr, port);
                break;

            case 3:
                System.out.println("set role, nc, dim");
                role = reader2.nextInt();
                nc = reader2.nextInt();
                dim = reader2.nextInt();
                setparams(RD);
                min_euc_dist.run(role, nc, dim, secpram, bitlen, addr, port);
                break;

            default:
                System.out.println("Invalid Input!!!");
                break;
        }
    }
}
