package ternary_tree;

import java.util.Collections;
//import java.util.ArrayList;
import java.util.Vector;

public class Fonemas {

	Tree tree = new Tree();
	
	void reset()
	{
		tree = new Tree();
	}
	
	void ADD(String code)
	{
		String fonema1 = code.substring(0, 2);
		String fonema2 = code.substring(3, 5);
		String fonema3 = code.substring(6, 8);
		tree.ADD(fonema1, fonema2, fonema3);
	}
	
	Vector<String> combinations()
	{
		Vector<String> comb = new Vector<String>();
		for(String i : tree.combinations(tree.getRoot()))
		{
			comb.add(i.substring(1, i.length()));
		}
		return comb;
	}
	
	Vector<String> generateFonemas() 
	{
		Vector<String> fonemas = new Vector();
		
		fonemas.add(new String("BA"));
		fonemas.add(new String("BE"));
		fonemas.add(new String("BO"));
		fonemas.add(new String("CA"));
		fonemas.add(new String("CE"));
		fonemas.add(new String("CO"));
		fonemas.add(new String("DA"));
		fonemas.add(new String("DE"));
		fonemas.add(new String("DO"));
		fonemas.add(new String("FA"));
		fonemas.add(new String("FE"));
		fonemas.add(new String("FO"));
		fonemas.add(new String("GA"));
		fonemas.add(new String("GE"));
		fonemas.add(new String("GO"));
		fonemas.add(new String("HA"));
		fonemas.add(new String("HE"));
		fonemas.add(new String("HO"));
		
		Collections.shuffle(fonemas);
		
		return fonemas;		
	}
	
	Vector<String> generateCodes(Vector<String> fonemas)
	{
		Vector<String> codes = new Vector<String>();

		for(int i = 0; i < fonemas.size(); i+=3)	
		{
			Vector<String> aux = new Vector<String>();
			aux.add(fonemas.get(i));
			aux.add(fonemas.get(i+1));
			aux.add(fonemas.get(i+2));
			Collections.sort(aux);
			codes.add(aux.get(0)+"-"+aux.get(1)+"-"+aux.get(2));
		}
		return codes;
	}
	
}

