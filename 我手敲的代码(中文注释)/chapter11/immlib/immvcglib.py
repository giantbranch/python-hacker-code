#!/usr/bin/env python

"""
Reads vcg buffer and creates the graph using Immunity Debugger lib

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>}


"""

__VERSION__ = '1.2'


"""
NOTES:
need to divide graph in layers
save max layer in graph
every set of childs [unique and different part vertex] E a different layer
save vertex of layer in each layer
mark blank path points in each layer [i preffer path points to dummy vertices] 

for layer in layers:
   move east and west vertices, depending on their type *

pathfinder(graph)
  search empy spots where edge lines might travel
  
  
a cool thing might be mark the whole graph as east-slanted or west-slanted, according the graph
the n east or n west it will move

if the graph is slanting too much to east from center point, we can start thinking on going west
that can be too fuzzy, but will try to make an aproach for human eye


new lib against old lib:
orphan vertices from old lib has been solved, now every vertex has at least 1 relationship saved 
parent<->child type of vertex are correctly relationed now

"""

import graphclass

import immlib
import debugger
#chaos is our friend 
# XXX: Sure .. but how does chaos theory relate to random human interaction?
# XXX: Chance meetings that ultimately end up derailing your life ..
# XXX: The butterfly effect of hello's .. I don't know .. do you?
from random import randint

# default GRAPH palette
PALETTE = []

PALETTE.append("manhattan_edges: yes\r\n")
PALETTE.append("layoutalgorithm: mindepth\r\n")
PALETTE.append("finetuning: no\r\n")
PALETTE.append("layout_downfactor: 100\r\n")
PALETTE.append("layout_upfactor: 0\r\n")
PALETTE.append("layout_nearfactor: 0\r\n")
PALETTE.append("xlspace: 12\r\n")
PALETTE.append("yspace: 30\r\n")
PALETTE.append("colorentry 32: 0 0 0\r\n")
PALETTE.append("colorentry 33: 0 0 255\r\n")
PALETTE.append("colorentry 34: 0 0 255\r\n")
PALETTE.append("colorentry 35: 128 128 128\r\n")
PALETTE.append("colorentry 36: 128 128 128\r\n")
PALETTE.append("colorentry 37: 0 0 128\r\n")
PALETTE.append("colorentry 38: 0 0 128\r\n")
PALETTE.append("colorentry 39: 0 0 255\r\n")
PALETTE.append("colorentry 40: 0 0 255\r\n")
PALETTE.append("colorentry 41: 0 0 128\r\n")
PALETTE.append("colorentry 42: 0 128 0\r\n")
PALETTE.append("colorentry 43: 0 255 0\r\n")
PALETTE.append("colorentry 44: 0 128 0\r\n")
PALETTE.append("colorentry 45: 255 128 0\r\n")
PALETTE.append("colorentry 46: 0 128 0\r\n")
PALETTE.append("colorentry 47: 128 128 255\r\n")
PALETTE.append("colorentry 48: 255 0 0\r\n")
PALETTE.append("colorentry 49: 128 128 0\r\n")
PALETTE.append("colorentry 50: 1 1 1\r\n")
PALETTE.append("colorentry 51: 192 192 192\r\n")
PALETTE.append("colorentry 52: 0 0 255\r\n")
PALETTE.append("colorentry 53: 0 0 255\r\n")
PALETTE.append("colorentry 54: 0 0 255\r\n")
PALETTE.append("colorentry 55: 128 128 128\r\n")
PALETTE.append("colorentry 56: 128 128 255\r\n")
PALETTE.append("colorentry 57: 0 128 0\r\n")
PALETTE.append("colorentry 58: 0 0 128\r\n")
PALETTE.append("colorentry 59: 0 0 255\r\n")
PALETTE.append("colorentry 60: 128 0 128\r\n")
PALETTE.append("colorentry 61: 0 128 0\r\n")
PALETTE.append("colorentry 62: 0 128 0\r\n")
PALETTE.append("colorentry 63: 0 128 64\r\n")
PALETTE.append("colorentry 64: 0 0 128\r\n")
PALETTE.append("colorentry 65: 0 0 128\r\n")
PALETTE.append("colorentry 66: 255 0 255\r\n")
PALETTE.append("colorentry 67: 128 128 0\r\n")
PALETTE.append("colorentry 68: 0 0 128\r\n")
PALETTE.append("colorentry 69: 0 0 255\r\n")
PALETTE.append("colorentry 70: 0 0 128\r\n")
PALETTE.append("colorentry 71: 0 0 255\r\n")
PALETTE.append("colorentry 72: 0 0 0\r\n")
PALETTE.append("colorentry 73: 255 255 255\r\n")
PALETTE.append("colorentry 74: 192 192 192\r\n")
PALETTE.append("colorentry 75: 0 255 255\r\n")
PALETTE.append("colorentry 76: 0 0 0\r\n")
PALETTE.append("colorentry 77: 128 0 0\r\n")
PALETTE.append("colorentry 78: 128 128 128\r\n")
PALETTE.append("colorentry 79: 128 128 0\r\n")
PALETTE.append("colorentry 80: 255 0 255\r\n")
PALETTE.append("colorentry 81: 0 0 0\r\n")
PALETTE.append("colorentry 82: 0 0 255\r\n")
PALETTE.append("colorentry 83: 0 0 0\r\n")

class graphTree:
    # address to call tree from, ID immlib.Debugger() object
    def __init__(self, address, imm):
        """ Init the graphing object """
        self.imm = imm
        self.callTree = imm.getCallTree(address)
        self.address = address

    def orderNodesFromTree(self):
        """ return a call ordered list of nodes """

        # call[0] -> line number in column
        # call[1] -> dummy (must be 1)
        # call[2] -> type (set of TY_xxx)
        # call[3] -> entry (address of function)
        # call[4] -> from (address of calling function)
        # call[5] -> calls to (address of called subfunction)

        # so really for now we just do up and down for the first entry
        TARGET = []
        PARENTS = []
        CHILDREN = []
        
        for call in self.callTree:
            if call[3]:
                if "0x%X"%call[3] not in TARGET:
                    TARGET.append("0x%X"% call[3])
            if call[4]:
                if "0x%X"%call[4] not in PARENTS:
                    PARENTS.append("0x%X"% call[4])
            if call[5]:
                if "0x%X"%call[5] not in CHILDREN:
                    CHILDREN.append("0x%X"% call[5])
            
        return TARGET, PARENTS, CHILDREN

    def makeNode(self, title, content = "", vertical_order = 0):
        """ build a simple node VCG buf entry """
        node = []
        node.append('node: {\r\n')
        node.append('title: "%s"\r\n'% title)
        node.append('vertical_order: %d\r\n'% vertical_order)
        if content != "":
            node.append('label: "\x0c69%s\x0c31\r\n%s"\r\n'% (title, content))
        else:
            node.append('label: "\x0c69%s\x0c31\r\n'% title)
        node.append('}\r\n')
        return node

    def makeEdge(self, source, target, label = "", color = "green"):
        """ work out the relations between the boxies """
        # we call these 'edges', edges basically connect the boxies
        edge = []

        edge.append('edge: {\r\n')
        edge.append('sourcename: "%s"\r\n'% source)
        edge.append('targetname: "%s"\r\n'% target)
        if label != "":
            edge.append('label: "%s"\r\n'% label)
        edge.append('color: %s\r\n'% color)
        edge.append('}\r\n')

        return edge

    def makeVCG(self, title, nodes = [], edges = []):
        """ build a simple node tree VCG buffer """
        vcg = []

        vcg.append('graph: {\r\n')
        # XXX: dummy title (0xaddress) so parser doesn't choke .. fix that
        vcg.append('title: "%s"\r\n'% title)

        # add default palette
        for line in PALETTE:
            vcg.append(line)

        # add nodes, nodes is a list of node entries
        for node in nodes:
            for line in node:
                vcg.append(line)

        # work out the relations from the call tree
        for edge in edges:
            for line in edge:
                vcg.append(line)

        # close the graph
        vcg.append('}\r\n')

        return vcg

    def graphCallTree(self):
        """ pop up a call tree graph for this address """
        TARGET, PARENTS, CHILDREN = self.orderNodesFromTree()

        nodes = []
        unique = []
        # make sure we don't double up on nodes ..
        for title in TARGET+PARENTS+CHILDREN:
            if title not in unique:
                unique.append(title)
                
        # make nodes for all the entries
        for title in unique:
            
            if title in PARENTS:
                order = 0
            if title in TARGET:
                order = 1
            if title in CHILDREN:
                order = 2
                
            # try to resolve to symbol using decodeAddress()
            node_content = self.imm.decodeAddress(int(title, 16))
            nodes.append(self.makeNode(title, content = node_content, vertical_order = order))

        edges = []
        # we want to connect all the parents to the target and the target to all the children
        target = TARGET[0]
        
        for parent in PARENTS:
            ### makeEdge(source-node, target-node)
            edges.append(self.makeEdge(parent, target))
        for child in CHILDREN:
            edges.append(self.makeEdge(target, child))

        # make the main VCG
        vcg = self.makeVCG("Call Graph <-for-> %s [0x%X]"% (self.imm.decodeAddress(self.address), self.address), nodes, edges)
        
        # XXX: debug write out
        fd = open("CALLTREE.vcg", "w")
        for line in vcg:
            fd.write(line)
        fd.close()

        # pop up the MDI window
        generateGraphFromBuf(vcg)

class ParseVCGList:
    """ recursive VCG parser """
    
    def __init__(self, vcgList):
        """ pre-process our shiznit """
        self.sep = '!SEP!'
        self.DEBUG = False
    
        # XXX: need to implement the full VCG grammar at some point
        # XXX: also see http://www.penguin-soft.com/penguin/man/1/vcg.html
        
        # WHEN MOVING TO MORE COMPLEX VCG, ADD FUNCTIONALITY _HERE_
        self.MODETOKENS = [ 'graph:', 'node:', 'edge:' ]
        
        self.VARTOKENS  = [ 'title:', 'label:', 'vertical_order:', 'horizontal_order:', 'manhattan_edges:', 'layoutalgorithm:' ]
        self.VARTOKENS += [ 'finetuning:', 'layout_downfactor:', 'layout_upfactor:' ]
        self.VARTOKENS += [ 'layout_nearfactor:', 'xlspace:', 'yspace:' ]
        self.VARTOKENS += [ 'sourcename:', 'targetname:', 'color:' ]
        
        # strip comment lines ...
        cleanVCG = []
        # in string mode we don't want to replace .. 
        sMode = False
        
        for line in vcgList:
            
            # skip comments ...
            if line[:2] == "//":
                continue
            
            clean = []
            lineList = list(line)
            
            for c in lineList:
                if c == '"':
                    # flip pre-process mode
                    sMode = not sMode
                    
                if sMode == True: # string mode open
                    clean.append(c)
                else:
                    if c in ['\r']: # stripped chars ..
                        continue
                    if c in ['\n', ' ']:
                        clean.append(self.sep)
                    else:
                        clean.append(c)
                        
            line = ''.join(clean)
            
            if len(line):
                cleanVCG.append(line)
        
        self.vcgText = ''.join(cleanVCG)
        
        self.nodeList = []
        self.edgeList = []
        self.graphList = []
        
        self.lastMode = ""
        
    def error(self, error):
        """ raise an error exception """
        raise error

    def reParse(self, vcgItems, mode = ""):
        """ used for recursive parse """
        
        # DEBUG LOGS
        if self.DEBUG:
            logger = immlib.Debugger()
            logger.Log(repr(vcgItems))
                    
        # if not empty == True .. recursive calls .. bla bla
        if vcgItems:
                    
            if vcgItems[0] in self.MODETOKENS:
                mode = vcgItems[0]
                self.lastMode = mode
                self.reParse(vcgItems[1:], mode = mode)
                
            elif vcgItems[0] in self.VARTOKENS or 'colorentry' in vcgItems[0]:
     
                ### Special case color entry ...
                if 'colorentry' in vcgItems[0]:
                    vcgItems[0] = " ".join([vcgItems[0], vcgItems[1]])
                    del vcgItems[1]
                        
                args = []
                key = vcgItems[0]
                        
                i = 1
                while vcgItems[i] not in self.VARTOKENS and vcgItems[i] not in self.MODETOKENS and 'colorentry' not in vcgItems[i]:
                    if '}' in vcgItems[i]:
                        break 
                    args.append(vcgItems[i])
                    i += 1
                        
                if mode == 'node:' and len(self.nodeList):
                    self.nodeList[len(self.nodeList)-1][key] = " ".join(args)
                        
                if mode == 'edge:' and len(self.edgeList):
                    self.edgeList[len(self.edgeList)-1][key] = " ".join(args)
                        
                if mode == 'graph:' and len(self.graphList):
                    self.graphList[len(self.graphList)-1][key] = " ".join(args)
                    
                self.reParse(vcgItems[i:], mode = self.lastMode)
                
            elif '{' in vcgItems[0]:

                # decide if mode needs a new dict .. or if it's just a pair: val
                if mode == 'graph:':
                    self.graphList.append({})
                elif mode == 'node:':
                    self.nodeList.append({})
                elif mode == 'edge:':
                    self.edgeList.append({})
                    
                self.reParse(vcgItems[1:], mode = mode)
            
            # close control block, go up one mode
            elif '}' in vcgItems[0]:
                self.reParse(vcgItems[1:], mode = '')
                    
        # all done ..
        return self.graphList, self.nodeList, self.edgeList
                
    def parseGraph(self):
        """ Parse a VCG graph .. not 100% proper .. but proper enough """
        vcgItems = self.vcgText.split(self.sep)
        return self.reParse(vcgItems)

def testVCGParse(path):
    """ test our new VCG parsing logic """
    vcgList = []

    fd = open(path, 'r')
    for line in fd:
        vcgList.append(line)
    fd.close()

    parser = ParseVCGList(vcgList)
    
    # these are lists of dicts :> so 1 dict per node/edge/graph
    graph, nodes, edges = parser.parseGraph()
    
    logger = immlib.Debugger()
    
    logger.Log("GRAPH:")
    for gDict in graph:
        for key in gDict:
            logger.Log("KeyVal: %s"% key)
            logger.Log(repr(gDict[key]))
    logger.Log("EDGES:")
    for eDict in edges:
        for key in eDict:
            logger.Log("KeyVal: %s"% key)
            logger.Log(repr(eDict[key]))
    logger.Log("NODES:")
    for nDict in nodes:
        for key in nDict:
            logger.Log("KeyVal: %s"% key)
            logger.Log(repr(nDict[key]))
    
    return
    
# re-done for new parser code
def generateGraphFromBuf(buf):
    # XXX: the new parser returns 3 lists of dicts .. for the graph, nodes, and edges
    # XXX: so then you can just go 'for nodeDict in nodes: handleNode(nodeDict)' etc.
    # XXX: the new parser doesn't care about specific filelayouts and uses recursion

    parser = ParseVCGList(buf)
    # these are lists of dicts :> so 1 dict per node/edge/graph
    GRAPH, NODES, EDGES = parser.parseGraph()
    
    # 1. get the graph title (assuming only one VCG graph per .vcg)
    title = GRAPH[0]['title:']
    
    # 2. get the start address
    try:
        # XXX: we wanna get rid of splits for parsing eventually :>
        start_address = title.split("(")[1][:8]
    except:
        start_address = "0xcafebabe"
    
    # DO GRAPHICS MUCK
    Draw = graphclass.Draw()
    # Get mdi handler
    DrawHandler = Draw.createGraphWindow(title, start_address)
    G = graphclass.Graph()
    # Link the window handler to our graph
    G.setHandler(DrawHandler)
    
    # 3. handle NODES
    vertices = createVertexList(NODES, DrawHandler)
    
    # Once we has the vertices and the buffers we can calculate every vertex absolute size
    for vertex in vertices:
        vertex.calculateAbsoluteSize(vertex.getVertexBuffer())
    # Add list of vertex objects to graph instance
    G.addVertices(vertices) 
    # Create edge list for graph instance + adjlists for vertex instance
    createAdjacencyList(G, vertices, EDGES)
    
    """
    at this point we have:
    * draw instance [graph window inside debugger]
    * graph instance 
      * vertex instances list
      * edges lists + properties [true, false, direct]
    * vertex instances list
      * buffers
      * absolute sizes
      * adj lists of in and out edges
    we now need to iterate our lists and define the best way to place
    vertices
    """
    
    # First attempt, place according true/false logic
    firstAttemptToPlace(vertices)
    # Was first attempt enough?
    finalAttemptToPlace(vertices)
    # Get the new startCoords
    adjustStartCoords(vertices, G)
    # Set the bitmap size
    G.setBitSize(vertices)
    # Try to get the best path for edges
    edgelist = pathFinder(vertices)
    # Draw lines
    drawEdges(edgelist, DrawHandler)
    # Draw boxes
    drawVertices(vertices)
    ### not here
    ###checkPlanarity(vertices)
    # splash the graph onto screen
    G.splashTime()
    

def generateGraph(address):
    """ generates a VCG given a function address """
    try:
        vcg = generateVCG(address)
    except:
        print "[XXX] Error generating VCG"        
        return 
    
    # XXX: replaces old duplicate, duplicating code is bad mmkay
    generateGraphFromBuf(vcg)
    

def adjustStartCoords(vertices,G):
    (x,y)=vertices[0].getStartCoords()
    (h,w)=G.getBitSize()
    temp=w/2
    #debugger.Error("%s - %s" % (str(x), str(temp)))
    for vertex in vertices:
        vertex.moveEast(x+temp)
        
        
# handles nodes - re-done for new parser
def createVertexList(nodes, handler):
    """ iterate vcg file to get vertex list and vertices's buffers"""
    vertices = []
    
    for node in nodes:
        vertexbuf = []
        v = graphclass.Vertex(handler)

        logger = immlib.Debugger()
        # XXX: assuming control chars are always there
        label = node['label:']
        content = label[label.find("\x0c31") + 3:]
        content = content.replace('"', '')
        label = label[label.find("\x0c69") + 3 : label.find("\x0c31")]

        v.setLabel(label)
        
        title = node['title:']
        v.setName(title)
        vertices.append(v)
        
        vertexbuf += [v.getLabel()]
        for key in node:
            if key not in ['vertical_order:', 'title:', 'label:']:
                nodeLine = node[key]
                vertexbuf += [' '.join([key, node[key]])]
                
        # add content to node box ... strings are kept intact newlines and all by preprocessor
        content = content.split('\r\n')
        for line in content:
            # skip empty lines
            if len(line):
                vertexbuf += [line]
        
        v.setVertexBuffer(vertexbuf)
        
    return vertices
        
    #for a in range(15,len(buf)):
    #   if buf[a][:6] == "node: ":
    #        vertexbuf=[]
    #        v=graphclass.Vertex(handler)
    #        v.setLabel(buf[a].split("\"")[3].split("\x0c")[1][2:])
    #        v.setName(buf[a].split("\"")[1])
    #        vertices.append(v)
    #        #fill vertex buffer
    #        vertexbuf+=[v.getLabel()]
    #        #immlib.Error("node: " + v.getName() +" Labeled: " + v.getLabel())
    #        
    #    #if a > 20: #skip options in vcg header
    #    if buf[a][:6] != "node: " and buf[a][:2] != "//" and buf[a][:10] !="colorentry":
    #        if buf[a].find("}") == -1:
    #            vertexbuf+=[buf[a]]
    #        else:
    #            #we dont want to add blank vertexbuf or to a non existant vertex
    #            if vertexbuf and v:
    #                v.setVertexBuffer(vertexbuf[:-1])
    #                vertexbuf=[]
    #return vertices

def finalAttemptToPlace(vertices):
    #flag = False
    #while not flag:
        #for vertex in vertices:
            #ret=checkForPlacedVertex(vertex,vertices)
            #if not ret:
                #flag = True
    for a in range(1,15):
        for vertex in vertices:
            checkForPlacedVertex(vertex,vertices)
     
def searchForDummyPathsH2South(edgelist,vertices):
    templist=edgelist
    vertexlist=[]
    (xl,yl,x2l,y2l,color) = edgelist[-1]
    for vertex in vertices:
        (x,y,x2,y2) = vertex.getCoords()
        #if vertex.getName() == "40fa96":
            #f.write("%s: xl: %d, yl: %d, x2l: %d, y2l: %d\tx: %d, y: %d, x2: %d, y2: %d\n" % (vertex.getName(), xl, yl, x2l, y2l, x, y , x2, y2))
        if xl >= x-5 and xl <= x2+5 and yl < y and y2l > y:
            vertexlist.append(vertex)
            
    return applyDummyPathsH2South(vertexlist,edgelist)

def searchForDummyPathsH2North(edgelist,vertices):
    templist=edgelist
    vertexlist=[]
    (xl,yl,x2l,y2l,color) = edgelist[-1]
    for vertex in vertices:
        (x,y,x2,y2) = vertex.getCoords()
        if xl >= x-5 and xl <= x2+5 and yl > y and y2l < y:
            vertexlist.append(vertex)
            
    return applyDummyPathsH2North(vertexlist,edgelist)

"""
NOTES:

if i use an edge templist i might be able to grep off
the non usefull bendings:

  --| 
  __|
  
  =>
  
  |
  |

another nice thing would be to check wheter im nearest to east or west of
the overlapped vertex, so i can decide where to escape
"""


def applyDummyPathsH2SouthTrue(vertexlist,edgelist):
    (xl,yl,x2l,y2l,color) = edgelist[-1]
    vertexlist.sort()
    for vertex in vertexlist:
        (x,y,x2,y2) = vertex.getCoords()
        cm = randint(-20,-10)
        
        if y2l-5 > y and y2l <= y2 and len(vertexlist) == 1: # line overlapp part of vertex, but it doesnt cross all over it
            (tx,ty,tx2,ty2,color) = edgelist[-1]
            edgelist[-1] = (( tx,ty,tx2, y-10, color))
        else:
            if vertexlist.index(vertex) == 0:
                edgelist[-1] = ((xl,yl,xl,y-10,color))
            else:
                pass
                #edgelist.append((endx,endy,endx,y-10,color))
            #edgelist[-1] = ((xl,yl,xl,y-10,color))
            edgelist.append((xl,y-10,x-10+cm,y-10,color))
            edgelist.append((x-10+cm,y-10,x-10+cm,y2+10,color))
            if vertex != vertexlist[-1]: #leave pathfinder() do the last stroke
                edgelist.append((x-10+cm,y2+10,xl,y2+10,color))
            endx=xl
            endy=y2+10
            #edgelist.append((xl,y2+10,xl,endy,color))
        
    return edgelist

def applyDummyPathsH2South(vertexlist,edgelist):
    (xl,yl,x2l,y2l,color) = edgelist[-1]
    vertexlist.sort()
    for vertex in vertexlist:
        (x,y,x2,y2) = vertex.getCoords()
        if y2l > y and y2l <= y2 and len(vertexlist) == 1: # line overlapp part of vertex, but it doesnt cross all over it
            (tx,ty,tx2,ty2,color) = edgelist[-1]
            edgelist[-1] = (( tx,ty,tx2, y-10, color))
        else:
            if vertexlist.index(vertex) == 0:
                edgelist[-1] = ((xl,yl,xl,y-10,color))
            else:
                pass
                edgelist.append((endx,endy,endx,y-10,color))
            #edgelist[-1] = ((xl,yl,xl,y-10,color))
            if x2 - xl < xl -x: # go for the eastern exit
                cm = randint(-5,5)
                edgelist.append((xl,y-10,x2+20+cm,y-10,color))
                edgelist.append((x2+20+cm,y-10,x2+20+cm,y2+10,color))
                if vertex != vertexlist[-1]: #leave pathfinder() do the last stroke
                    edgelist.append((x2+20+cm,y2+10,xl,y2+10,color))
                endx=xl
                endy=y2+10
            else: #western exit
                cm = randint(-20,-10)
                edgelist.append((xl,y-10,x-10+cm,y-10,color))
                edgelist.append((x-10+cm,y-10,x-10+cm,y2+10,color))
                if vertex != vertexlist[-1]: #leave pathfinder() do the last stroke
                    edgelist.append((x-10+cm,y2+10,xl,y2+10,color))
                endx=xl
                endy=y2+10
            
            #edgelist.append((xl,y2+10,xl,endy,color))
        
    return edgelist


def applyDummyPathsH2North2(vertexlist,edgelist):
    (xl,yl,x2l,y2l,color) = edgelist[-1]
    vertexlist.sort()
    vertexlist.reverse()
    for vertex in vertexlist:
        (x,y,x2,y2) = vertex.getCoords()
        if y2l > y and y2l <= y2 and len(vertexlist) == 1: # line overlapp part of vertex, but it doesnt cross all over it
            pass
            #(tx,ty,tx2,ty2,color) = edgelist[-1]
            #edgelist[-1] = (( tx,ty,tx2, y-10, color))
        else:
            if vertexlist.index(vertex) == 0:
                edgelist[-1] = ((xl,yl,xl,y2+10,"Blue"))
            else:
                pass
                edgelist.append((endx,endy,endx,y-10,"Aqua"))
            #edgelist[-1] = ((xl,yl,xl,y-10,color))
            #if x2 - xl < xl -x: # go for the eastern exit
            cm = randint(-5,5)
            edgelist.append((xl,y2+10,x2+20+cm,y2+10,"red"))
            edgelist.append((x2+20+cm,y2+10,x2+20+cm,y-10,"Yellow"))
            if vertex != vertexlist[-1]: #leave pathfinder() do the last stroke
                edgelist.append((x2+20+cm,y2+10,xl,y2+10,"Maroon"))
            endx=xl
            endy=y-10
                
            #else: #western exit
                #cm = randint(-5,5)
                #edgelist.append((xl,y2+10,x-20+cm,y2+10,color))
                #edgelist.append((x-20+cm,y2+10,x-20+cm,y-10,color))
                #if vertex != vertexlist[-1]: #leave pathfinder() do the last stroke
                    #edgelist.append((x-20+cm,y2+10,xl,y2+10,color))
                #endx=xl
                #endy=y2+10
             #   pass
                
            
            #edgelist.append((xl,y2+10,xl,endy,color))
            
    return edgelist

def applyDummyPathsH2North(vertexlist,edgelist):
    (xl,yl,x2l,y2l,color) = edgelist[-1]
    vertexlist.sort()
    vertexlist.reverse()
    for vertex in vertexlist:
        (x,y,x2,y2) = vertex.getCoords()
        if y2l > y and y2l <= y2 and len(vertexlist) == 1: # line overlapp part of vertex, but it doesnt cross all over it
            (tx,ty,tx2,ty2,color) = edgelist[-1]
            edgelist[-1] = (( tx,ty,tx2, y-10, color))
        if vertexlist.index(vertex) == 0:
            edgelist[-1] = ((xl,yl,xl,y2+10,color))
        else:
            edgelist.append((endx,endy,endx,y2+10,color))
            
        cm = randint(-5,5)
        if x2 - xl < xl -x: # go for the eastern exit
            edgelist.append((xl,y2+10,x2+20+cm,y2+10,color))
            edgelist.append((x2+20+cm,y2+10,x2+20+cm,y-10,color))
            if vertex != vertexlist[-1]: #leave pathfinder() do the last stroke
                edgelist.append((x2+20+cm,y-10,xl,y-10,color))
            endx=xl
            endy=y-10
        else:
            edgelist.append((xl,y2+10,x-20+cm,y2+10,color))
            edgelist.append((x-20+cm,y2+10,x-20+cm,y-10,color))
            if vertex != vertexlist[-1]: #leave pathfinder() do the last stroke
                edgelist.append((x-20+cm,y-10,xl,y-10,color))
            endx=xl
            endy=y-10
            
    return edgelist
    

def searchForDummyPathsW(edgelist,vertices):
    return
    (xl,yl,x2l,y2l,a) = edgelist[-1]
    for vertex in vertices:
        (x,y,x2,y2) = vertex.getCoords()
        if xl > x or yl < x2 and x2l > y2:
            pass
        else:
            f=open("ea.txt","w+")
            f.write("quilombo %s\n" % str(x))
            f.close()
    return edgelist

def pathFinder(vertices):
    """find edge's path
    To find an endge path we start joining two vertex with 3 basic strokes, 
    A -> B -> C
    after placing each of this basci strokes we check if it is not overlapping a vertex, if so
    we decide a alternate path based on dummy blank points
    A -> A' -> A'' -> B -> C
    where A' (x2,y2) is the original A (x2,y2) so the next basic stroke B, knows how
    to keep going
    
    """
    """note on adding edges to edgelist:
    since edgelist will self modify with other functions if pretty important
    to add relative values and not absolute values.
    ie: before adding a new edge check the last one, and the new values must be relative to edgelist[-1]
    """
    edgelist=[]
    f=open("edges.txt","w")
    for vertex in vertices:
        (x,y,x2,y2) = vertex.getCoords()
        parentw=vertex.getWidth()
        parenth=vertex.getHeight()
        outadj=vertex.getOutAdj()
        for child in outadj:
            if child[1] == 1:  #true child
                for vertexchild in vertices:
                    if child[0] == vertexchild.getName():
                        if vertex.getName() == vertexchild.getName():
                            # parent = child, then loop in same vertex
                            edgelist.append((parentw*1/4+x+chaosmov,parenth+y-1,parentw*1/4+x+chaosmov,parenth+y+5,"darkgreen"))
                            edgelist.append((parentw*1/4+x+chaosmov,parenth+y+5,x-14,parenth+y+5,"darkgreen"))
                            edgelist.append((x-14,parenth+y+5,x-14,y-10,"darkgreen"))
                            edgelist.append((x-14,y-10,parentw*1/4+x+chaosmov,y-10,"darkgreen"))
                            edgelist.append((parentw*1/4+x+chaosmov,y-10,parentw*1/4+x+chaosmov,y-1,"darkgreen"))
                        else:
                            (xch,ych,x2ch,y2ch) = vertexchild.getCoords()
                            childw=vertexchild.getWidth()
                            #if x >= xp and x <= x2p:
                                #immlib.Error("%s and %s overlaps LEFT: %d" % (vertex.getName(),vertex2check.getName(),x2p-x))
                             
                            #if x2 >= xp and x <= x2p:
                                #immlib.Error("%s and %s overlaps RIGHT" % (vertex.getName(),vertex2check.getName()))
                            f.write("Edge true from %s (%d,%d,%d,%d) to %s (%d,%d,%d,%d)\n" % (vertex.getName(),x,y,x2,y2,vertexchild.getName(),xch,ych,x2ch,y2ch))
                            chaosmov=randint(-5, 0)
                            if (parenth+y-1) > ych-2-25: # go north
                                edgelist.append((parentw*1/4+x+chaosmov,parenth+y-1,parentw*1/4+x+chaosmov,parenth+y+5,"Blue"))
                                edgelist.append((parentw*1/4+x+chaosmov,parenth+y+5,x-14,parenth+y+5,"Blue"))
                                edgelist.append((x-14,parenth+y+5,x-14,ych-2-20+chaosmov,"Blue"))
                                edgelist=searchForDummyPathsH2North(edgelist,vertices)
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                edgelist.append((tx2,ty2,xch+(childw*1/2)+chaosmov,ty2,color))
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                if ty2 < y2ch: 
                                    edgelist.append((tx2,ty2,tx2,ych-2,color)) #last stroke enters from north
                                else:
                                    edgelist.append((tx2,ty2,tx2,y2ch-2,color)) # last stroke enters from south
                                #edgelist=searchForDummyPathsH2North(edgelist,vertices)
                            else: # go south
                                #starting line
                                edgelist.append((parentw*1/4+x+chaosmov,parenth+y-1,parentw*1/4+x+chaosmov,ych-2-25+chaosmov,"darkgreen"))
                                edgelist=searchForDummyPathsH2South(edgelist,vertices)
                                #bend line #1
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                edgelist.append((tx,ty2,xch+(childw*1/2)+chaosmov,ty2,color))
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                if ty2 < y2ch: 
                                    edgelist.append((tx2,ty2,tx2,ych-2,color)) #last stroke enters from north
                                else:
                                    edgelist.append((tx2,ty2,tx2,y2ch-2,color)) # last stroke enters from south
                                edgelist.append((tx2,ty2,tx2,ych-2,color))
                                
                            #add endpoint
                            addEndPointToEdge(edgelist)
                        
                        
            elif child[1] == 2 : #false child
                for vertexchild in vertices:
                    if child[0] == vertexchild.getName():
                        if vertex.getName() == vertexchild.getName():
                            # parent = child, then loop in same vertex
                            debugger.Error("loop false")
                            edgelist.append((parentw*1/4+x+chaosmov,parenth+y-1,parentw*1/4+x+chaosmov,parenth+y+5,"red"))
                            edgelist.append((parentw*1/4+x+chaosmov,parenth+y+5,x-14,parenth+y+5,"red"))
                            edgelist.append((x-14,parenth+y+5,x-14,y-10,"red"))
                            edgelist.append((x-14,y-10,parentw*1/4+x+chaosmov,y-10,"red"))
                            edgelist.append((parentw*1/4+x+chaosmov,y-10,parentw*1/4+x+chaosmov,y-1,"red"))
                            
                        else:
                            (xch,ych,x2ch,y2ch) = vertexchild.getCoords()
                            childw=vertexchild.getWidth()
                            chaosmov=randint(0, 5)
                            if (parenth+y-1) > ych-2-25: # go north
                                edgelist.append((parentw*3/4+x+chaosmov,parenth+y-1,parentw*3/4+x+chaosmov,parenth+y+5,"Blue"))
                                edgelist.append((parentw*3/4+x+chaosmov,parenth+y+5,x2+14,parenth+y+5,"Blue"))
                                edgelist.append((x2+14,parenth+y+5,x2+14,ych-2-20+chaosmov,"Blue"))
                                edgelist=searchForDummyPathsH2North(edgelist,vertices)
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                edgelist.append((tx2,ty2,xch+(childw*1/2)+chaosmov,ty2,color))
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                if ty2 < y2ch: 
                                    edgelist.append((tx2,ty2,tx2,ych-2,color)) #last stroke enters from north
                                else:
                                    edgelist.append((tx2,ty2,tx2,y2ch-2,color)) # last stroke enters from south
                            else: #go south
                                edgelist.append((parentw*3/4+x+chaosmov,parenth+y-1,parentw*3/4+x+chaosmov,ych-2-25+chaosmov,"red"))
                                edgelist=searchForDummyPathsH2South(edgelist,vertices)
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                edgelist.append((tx,ty2,xch+(childw*1/2)+chaosmov,ty2,color))
                                (tx,ty,tx2,ty2,color) = edgelist[-1]                                
                                edgelist.append((tx2,ty2,tx2,ych-2,color))
                                edgelist=searchForDummyPathsH2South(edgelist,vertices)
                            #add endpoint
                            addEndPointToEdge(edgelist)
                            
                        
                        
                        
                        
                        
            elif child[1] == 0 : #direct child
                for vertexchild in vertices:
                    if child[0] == vertexchild.getName():
                        if vertex.getName() == vertexchild.getName():
                            # parent = child, then loop in same vertex
                            debugger.Error("loop direct")
                        else:
                            (xch,ych,x2ch,y2ch) = vertexchild.getCoords()
                            f.write("Edge direct from %s (%d,%d,%d,%d) to %s (%d,%d,%d,%d)\n" % (vertex.getName(),x,y,x2,y2,vertexchild.getName(),xch,ych,x2ch,y2ch))
                            chaosmov=randint(-5, 5) 
                            chaosmovlastx=randint(-20,20)
                            childw=vertexchild.getWidth()
                            if (parenth+y-1) > ych-2-25: # go north
                                edgelist.append((parentw*1/2+x+chaosmov,parenth+y-1,parentw*1/2+x+chaosmov,parenth+y+5,"Blue"))
                                edgelist.append((parentw*1/2+x+chaosmov,parenth+y+5,x-10,parenth+y+5,"Blue"))
                                edgelist.append((x-10,parenth+y+5,x-10,ych-2-20+chaosmov,"Blue"))
                                edgelist=searchForDummyPathsH2North(edgelist,vertices)
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                edgelist.append((tx2,ty2,xch+(childw*1/2)+chaosmov,ty2,color))
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                if ty2 < y2ch: 
                                    edgelist.append((tx2,ty2,tx2,ych-2,color)) #last stroke enters from north
                                else:
                                    edgelist.append((tx2,ty2,tx2,y2ch-2,color)) # last stroke enters from south
                                
                            else: # go south
                                edgelist.append((parentw*1/2+x+chaosmov,parenth+y-1,parentw*1/2+x+chaosmov,ych-2-25+chaosmov,"Black"))
                                edgelist=searchForDummyPathsH2South(edgelist,vertices)
                                (tx,ty,tx2,ty2,color) = edgelist[-1]
                                edgelist.append((tx,ty2,xch+(childw*1/2)+chaosmov,ty2,color))
                                (tx,ty,tx2,ty2,color) = edgelist[-1]                                
                                edgelist.append((tx2,ty2,tx2,ych-2,color))
                                
                                
                                
                            #add endpoint
                            addEndPointToEdge(edgelist)
                            
                            
                        
    return edgelist

def addEndPointToEdge(edgelist):
    (endx,endy,endx2,endy2,color)=edgelist[-1]
    edgelist.append((endx2,endy2,endx2,endy2+2,color))
    edgelist.append((endx2,endy2,endx2,endy2-2,color))
    edgelist.append((endx2,endy2+2,endx2+2,endy2+2,color))
    edgelist.append((endx2,endy2+2,endx2-2,endy2+2,color))
    edgelist.append((endx2+2,endy2-2,endx2+2,endy2+3,color))
    edgelist.append((endx2-2,endy2-2,endx2-2,endy2+3,color))
    edgelist.append((endx2-2,endy2-2,endx2+2,endy2-2,color))
    
    return edgelist

def drawVertices(vertices):
    startx=None
    for vertex in vertices:
        if vertex.isDrawn() == False:
            if startx==None:
                startx=1
            else:
                startx=0
            checkForPlacedVertex(vertex,vertices)
            (x,y)=vertex.getRelPos()
            vertex.placeVertex(x,y,vertex.getVertexBuffer(),"Black","Gray",startx)
            vertex.setDrawn()
    
    return

def drawEdges(edgelist,handler):
    for line in edgelist:
        linej=graphclass.Line(handler)
        x_pos=line[0]
        y_pos=line[1]
        x_to=line[2]
        y_to=line[3]
        color=line[4]
        linej.draw(x_pos,y_pos,x_to,y_to,color)
    return
    

# handles edges - re-done for new parser
def createAdjacencyList(G, vertices, edges):
    """ creates a directed adjacency list for every vertex """
    for edge in edges:
        source = edge['sourcename:']
        target = edge['targetname:']

        type = 0
        if 'label:' in edge:
            if 'TRUE' in edge['label:'].upper():
                type = 1
            if 'FALSE' in edge['label:'].upper():
                type = 2
                
        G.addEdges((source, target, type))
        
        for vertex in vertices:
            if vertex.getName() == source:
                vertex.addOutAdj(target, type)
            if vertex.getName() == target:
                vertex.addInAdj(source)                
    return
    
#    for a in range(1,len(buf)):
#        if buf[a][:7] == "edge: {":
#            edge=buf[a].split("\n")
#            for b in edge:
#                if len(b) > 1:
#                    parse=b.split("\"")
#                    source=parse[1]
#                    target=parse[3]
#                    type=0
#                    if len(parse) == 7:
#                        if parse[5] == "true":
#                            type=1
#                        elif parse[5] == "false":
#                            type=2
#                    G.addEdges((source,target,type))
#                    #print "source: " + source + " target : " + target
#                    for vertex in vertices:
#                        if vertex.getName() == source:
#                            vertex.addOutAdj(target,type)
#                        elif vertex.getName() == target:
#                            vertex.addInAdj(source)
#    return

def checkPlanarity(vertices):
    #for a in range(0,10):
        #for vertex in vertices:
            #checkForPlacedVertex(vertex,vertices)
    return 

def firstAttemptToPlace(vertices):
    """First attempt to place vertices
    We are going to suppose Graph is planar and
    attempt to place vertices directly,
    in real world this wont happens, but at least
    we'll have temptative coords for every vertex"""
    
    for vertex in vertices:
        if vertices.index(vertex) == 0 :
            (x,y)=vertex.getStartCoords()
            vertex.setRelPos(x,y)
            (x,y,x2,y2)=vertex.getCoords()
            vertex.setPlaced()
            (x,y)=vertex.getRelPos()
            #vertex.placeVertex(x,y,vertex.getVertexBuffer(),"Black","Gray",0)
        outadj=vertex.getOutAdj()
        #immlib.Error("Parent: %s" % str(vertex.getName()))
        if len(outadj) > 0: #dont do if no childs
            for child in outadj:
                if child[1] == 1:
                    for vertexchild in vertices:
                        if child[0] == vertexchild.getName() and vertexchild.isPlaced() == False:
                            (xp,yp)=vertex.getRelPos()
                            if xp == 0: #this means that no parent is still defined, maybe a recursive cycle?
                                #immlib.Error("recursive cycle? check inadj list true")
                                """Note: usually we dont want to go back from Point of No Return,
                                but in this special case of vertex, we need to do it.
                                we should have in mind, that overlapping might occur, but we wont move south , instead
                                we need to move east/west"""
                                inadj=vertex.getInAdj()
                                for parent in inadj:
                                    for parentvertex in vertices:                                    
                                        if parent == parentvertex.getName():
                                            (xp,yp)=parentvertex.getRelPos()
                                            y=yp+parentvertex.getHeight()+55
                                            x=xp-(parentvertex.getWidth()*0.75)
                                            x=xp-100
                                            vertexchild.setRelPos(x,y)
                                            #checkForPlacedVertex(vertexchild, vertices)
                                            vertexchild.setPlaced()
                            else:
                                
                                y=yp+vertex.getHeight()+55
                                #x=xp-(vertex.getWidth()*0.75)
                                x=xp-100
                                vertexchild.setRelPos(x,y)
                                checkForPlacedVertex(vertexchild, vertices)
                                vertexchild.setPlaced()                                
                                
                            #immlib.Error("Child True: %s\nx: %s\ny:%s\nParent:%s  %s, %s" % (str(child[0]),str(x),str(y),vertex.getName(),str(xp),str(yp)))
                elif child[1] == 2 :
                    for vertexchild in vertices:
                        if child[0] == vertexchild.getName() and vertexchild.isPlaced() == False:
                            (xp,yp)=vertex.getRelPos()
                            if xp == 0:
                                """special case"""
                                #immlib.Error("recursive cycle? check inadj list false")
                                inadj=vertex.getInAdj()
                                #immlib.Error(str(inadj))
                                for parent in inadj:
                                    for parentvertex in vertices:                                    
                                        if parent == parentvertex.getName():
                                            (xp,yp)=parentvertex.getRelPos()
                                            y=yp+parentvertex.getHeight()+15
                                            #x=xp+(parentvertex.getWidth()*0.75)
                                            x=xp+parentvertex.getWidth()+50
                                            vertexchild.setRelPos(x,y)
                                            #checkForPlacedVertex(vertexchild, vertices)
                                            vertexchild.setPlaced()

                            else:
                                y=yp+vertex.getHeight()+55
                                #x=xp+(vertex.getWidth()*0.75)
                                x=xp+vertex.getWidth()+50
                                vertexchild.setRelPos(x,y)
                                checkForPlacedVertex(vertexchild, vertices)
                                vertexchild.setPlaced()

                            #immlib.Error("Child False: %s\nx: %s\ny:%s\nParent:%s  %s, %s" % (str(child[0]),str(x),str(y),vertex.getName(),str(xp),str(yp)))
                
                if child[1] == 0 :
                    for vertexchild in vertices:
                        if child[0] == vertexchild.getName() and vertexchild.isPlaced() == False:
                            (xp,yp)=vertex.getRelPos()
                            if xp == 0:
                                """special case"""
                                #immlib.Error("recursive cycle? check inadj list direct")
                                inadj=vertex.getInAdj()
                                #immlib.Error(str(inadj))
                                for parent in inadj:
                                    for parentvertex in vertices:                                    
                                        if parent == parentvertex.getName():
                                            (xp,yp)=parentvertex.getRelPos()
                                            y=yp+parentvertex.getHeight()+55
                                            x=xp+(parentvertex.getWidth()/2)
                                            vertexchild.setRelPos(x,y)
                                            #checkForPlacedVertex(vertexchild, vertices)
                                            vertexchild.setPlaced()
                                            
                                
                            else:
                                y=yp+vertex.getHeight()+55
                                x=xp+(vertex.getWidth()/2)
                                vertexchild.setRelPos(x,y)
                                checkForPlacedVertex(vertexchild, vertices)
                                vertexchild.setPlaced()
                                
                            #immlib.Error("Child Direct: %s\nx: %s\ny:%s\nParent:%s  %s, %s" % (str(child[0]),str(x),str(y),vertex.getName(),str(xp),str(yp)))
                
    return 
                    




def checkForPlacedVertex(vertex2check,vertices):
    
    """Note: needs to divide graph in layers
    
    Draft notes:    
    step 1 get temptative coords to place vertex
    step 2 check if coords overlaps already placed vertex

    step 2 a)
    first we have to check if (y,y2) of vertex is in range of the placed vertex, 
    
    if y >= yp and y <= y2p or y2 >= yp and y2 <= y2p:
    
    if that condition is true, means we have a vertex in the same y that an already placed vertex, so it might be
    possible of an overlapping to exists, so we are going to ask:

    if x >= xp and x <= x2p:
    if that condition is true, then we have an overlapping over the y coord of the vertex (left point)
    
    if x2 >= xp and x <= x2p:
    if that condition is true, then we have an overlapping over the y coord of the vertex (right point)
    
    and if does, check whether x or x2 is overlapping
    once we know that, we need to check wheter x or x2 of overlapped vertex is touched
    if x , move west x - 10 and recheck
    """
    ret=False
    (x,y,x2,y2) = vertex2check.getCoords()
    for vertex in vertices:
        if vertex.getName() == vertex2check.getName() :
            pass
        else:
            if 1 == 1:
                (xp,yp,x2p,y2p) = vertex.getCoords()               
                if y >= yp and y <= y2p or y2 >= yp and y2 <= y2p:
                    #immlib.Error("%s and %s are in the same x range" % (vertex.getName(),vertex2check.getName()))
                    if x >= xp and x <= x2p:
                        #immlib.Error("%s and %s overlaps LEFT: %d" % (vertex.getName(),vertex2check.getName(),x2p-x))
                        vertex2check.moveSouth(y2p-y+25)
                        (xp,yp,x2p,y2p) = vertex.getCoords()
                        (x,y,x2,y2) = vertex2check.getCoords()
                        ret=True
                    if x2 >= xp and x <= x2p:
                        #immlib.Error("%s and %s overlaps RIGHT" % (vertex.getName(),vertex2check.getName()))
                        vertex2check.moveSouth(y2p-y+25)
                        (xp,yp,x2p,y2p) = vertex.getCoords()
                        (x,y,x2,y2) = vertex2check.getCoords()
                        ret=True
    return ret                    
                    
def checkForPlacedVertex2(vertex2check,vertices):
    
    """Note: needs to divide graph in layers
    
    Draft notes:    
    step 1 get temptative coords to place vertex
    step 2 check if coords overlaps already placed vertex

    step 2 a)
    first we have to check if (y,y2) of vertex is in range of the placed vertex, 
    
    if y >= yp and y <= y2p or y2 >= yp and y2 <= y2p:
    
    if that condition is true, means we have a vertex in the same y that an already placed vertex, so it might be
    possible of an overlapping to exists, so we are going to ask:

    if x >= xp and x <= x2p:
    if that condition is true, then we have an overlapping over the y coord of the vertex (left point)
    
    if x2 >= xp and x <= x2p:
    if that condition is true, then we have an overlapping over the y coord of the vertex (right point)
    
    and if does, check whether x or x2 is overlapping
    once we know that, we need to check wheter x or x2 of overlapped vertex is touched
    if x , move west x - 10 and recheck
    """
    ret=False
    (x,y,x2,y2) = vertex2check.getCoords()
    for vertex in vertices:
        if vertex.getName() == vertex2check.getName() :
            pass
        else:
            if 1 == 1:
                (xp,yp,x2p,y2p) = vertex.getCoords()               
                if y >= yp and y <= y2p or y2 >= yp and y2 <= y2p:
                    immlib.Error("%s and %s are in the same x range" % (vertex.getName(),vertex2check.getName()))
                    if x >= xp and x <= x2p:
                        immlib.Error("%s and %s overlaps LEFT: %d" % (vertex.getName(),vertex2check.getName(),x2p-x))
                        vertex2check.moveSouth(20)
                        (xp,yp,x2p,y2p) = vertex.getCoords()
                        (x,y,x2,y2) = vertex2check.getCoords()
                        ret=True
                    if x2 >= xp and x <= x2p:
                        vertex2check.moveSouth(20)
                        immlib.Error("%s and %s overlaps RIGHT" % (vertex.getName(),vertex2check.getName()))
                        (xp,yp,x2p,y2p) = vertex.getCoords()
                        (x,y,x2,y2) = vertex2check.getCoords()
                        ret=True
    return ret                    

                   
def defineVertexRelation(vertices):
    #first vertex coords
    #x=300
    #y=10
    #vertices[0].setRelPos(x,y)
    
    #vertices[0].placeVertex(x,y,vertices[0].getVertexBuffer(),"Black","Blue",0)
    
    #draw[0].draw(draw[1],draw[2],draw[0].getNodeBuffer(),"Black","Blue",startx)
    return

# XXX: if it's rainy out, re-do this too ...
def generateVCG(address):
    """ this function will generate a vcg compatible buffer to create the graph """
    imm = immlib.Debugger()
    ret = imm.getFunctionBegin(address)
    if ret:
        address = ret
    f = imm.getFunction(address)
    buf=[]
    buf.append('graph: {\x0d\x0a')
    buf.append('title: "Graph of %s (0x%08x)"\r\n' % (f.getName(),int(f.start)))
    buf.append("//default palette\r\n")
    ### add the default palette
    buf += PALETTE
    basicblocks = f.getBasicBlocks()
    basicblocks.sort()
    #first basicblock
    buf.append('node: { title: "0x%08x" vertical_order: 0 label: "\x0c69%s (0x%08x):\x0c31\r\n' % (int(basicblocks[0].start),f.getName(),int(f.start)))
    instr=basicblocks[0].getInstructions(imm)
    for i in instr:
        if len(i.comment) > 0:
            buf.append("%s || %s\r\n" % (i.result,i.comment.replace("\"","")))
        else:
            buf.append("%s\r\n" % i.result)
    buf.append("\"")
             
    #from second the last one -1 basicblocks
    
    for a in range(1,len(basicblocks)):
        buf.append(" }\n")
        buf.append('node: { title: "0x%08x" label: "\x0c69 0x%08x\x0c31\n' % (int(basicblocks[a].start),int(basicblocks[a].start)))
        instr=basicblocks[a].getInstructions(imm)
        for i in instr:
            if len(i.comment) > 0:
                buf.append("%s || %s\r\n" % (i.result,i.comment.replace("\"","")))
            else:
                buf.append("%s\r\n" % i.result)
                
        buf.append('"\r\n')
    
    buf.append("}\r\n" )
    #generate edges list
    buf.append("//nodes edges\r\n")        
    for a in range(0,len(basicblocks)-1):
        (true,false) = basicblocks[a].getEdges()
        if false != 0:
            buf.append('edge: { sourcename: "0x%08x" targetname: "0x%08x" label: "false" color: red }\r\n' % (int(basicblocks[a].start),int(basicblocks[a].end)))
            buf.append('edge: { sourcename: "0x%08x" targetname: "0x%08x" label: "true" color: darkgreen }\r\n' % (int(basicblocks[a].start),int(true)))
        else:
            buf.append('edge: { sourcename: "0x%08x" targetname: "0x%08x" }\r\n' % (int(basicblocks[a].start),int(true)))
    buf.append("\n}\r\n")
    return buf

        
def saveVCG(address,filename):
    vcg_buf=generateVCG(address)
    if len(vcg_buf) > 0:
        fd=open(filename,"wb")
        for a in vcg_buf:
            fd.write(a)
        fd.close()
    else:
        debugger.Error("There is no VCG graph")
    

if __name__=="__main__":
    main()
