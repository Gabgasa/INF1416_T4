package ternary_tree;

import java.util.Vector;
import java.lang.Math;

public class Tree 
{
	Vector<Node> tree;
	
	Node root;
	
	int height;
	
	protected Tree() {
		tree = new Vector<Node>();
		createRoot();
	}
	
	private boolean createRoot()
	{
		if(tree.isEmpty())
		{
			height = 0;
			root = new Node(0);
			tree.add(root);
			return true;
		}
		return false;
	}
	
	Node getRoot()
	{
		return root;
	}
	
	
	String getFoneFromNode(int pos)
	{
		return tree.get(pos).getFone();
	}
	
	Node getNode(int pos)
	{
		return tree.get(pos);
	}	
	
	void addNode(String str)
	{
		Node node = new Node(tree.size());
		node.setFone(str);
		tree.add(node);
	}
	
	void ADD(String fonema1, String fonema2, String fonema3)
	{
		height += 1;
		double numElements = Math.pow(3,height);
		for(int i = 0; i < numElements; i+=3)
		{
			addNode(fonema1);
			addNode(fonema2);
			addNode(fonema3);
		}
	}
	
	Vector<String> combinations(Node node)
	{
		Vector<String> comb = new Vector<String>();
		if(node.getLeft() >= tree.size())
		{
			comb.add(node.getFone());
			
			return comb;
		}
		
		for(String str : combinations(getNode(node.getLeft())))
		{
			comb.add(node.getFone() + "-" + str);
		}
		for(String str : combinations(getNode(node.getMid())))
		{
			comb.add(node.getFone() + "-" + str);
		}
		for(String str : combinations(getNode(node.getRight())))
		{
			comb.add(node.getFone() + "-" + str);
		}

		return comb;
	}
}
