#!/usr/bin/env python
"""
Immunity Debugger Graph Lib

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} Graph API


"""

__version__ = '1.1'

import debugger

#colors from graphics.hpp

ImmDrawColors = {"Black":0,"Maroon":128,"Green":32768,"Olive":32896,"Navy":8388608,"Purple":8388736,"Teal":8421376,\
                    "Gray":8421504,"Silver":12632256,"Red":255,"Lime":65280,"Yellow":65535,"Blue":16711680,"Fuchsia":16711935,\
                    "Aqua":16776960,"LightGray":12632256,"DarkGray":8421504,"White":16777215,"MoneyGreen":12639424,\
                    "SkyBlue":15780518,"Cream":15793151,"MedGray":10789024,"red":255,"darkgreen":32768}



class Graph:
    def __init__(self):
        self.vertices=[]
        self.edges=[]
        self.nvertices=0
        self.nedges=0
        self.handler=0
        self.height=0
        self.width=0
    
    
    def setHandler(self,handler):
        self.handler=handler
        
    def addVertices(self,vertices):
        self.vertices=vertices
    
    def getVertices(self):
        return self.vertices
    
    def addEdges(self,edges):
        """edges[0] = source
        edges[1] = target
        edges[3] = type
        type can be one of:
        Direct = 0
        True = 1
        False = 2"""
        self.edges.append(edges)
    
    def getEdges(self):
        return self.edges
    
    def getNEdges(self):
        self.nedges=len(self.edges)
        return self.nedges
    
    def getNVertices(self):
        self.nvertices=len(self.vertices)
        return self.nvertices
    
    def splashTime(self):
        return debugger.Splashtime(self.handler,self.height,self.width)
    
    
    def setBitSize(self,vertices):
        fy2=fx2=fx=fy=0
        for vertex in vertices:
            (x,y,x2,y2)=vertex.getCoords()
            if y2>fy2:
                fy2=y2
            if x2 > fx2:
                fx2=x2
            if y < fy:
                fy=y
            if  x < fx:
                fx=x
        self.height=fy2 + 200
        self.width = fx2 + 400 + abs(fx)
        vertices[0].setStartCoords(self.height,self.width)
                
    def getBitSize(self):
        return (self.height,self.width)
        
            
            
                
                
            
    
        
        
 
class Vertex:
    def __init__(self,handler):
        self.inadj=[]
        self.outadj=[]
        self.name=""
        self.label=""
        self.buf=[]
        #size is represented by absolute coords (x,y)
        self.absy=0  
        self.absx=0
        self.handler=handler
        self.x1=0
        self.y1=0
        self.x2=0
        self.y2=0
        self.rely=0
        self.relx=0
        self.color="Black"
        self.texth=0
        self.textw=0
        self.drawn=False
        self.placed=False
        self.start_x=300
        self.start_y=10
        
    def __cmp__(self, other):
        return cmp(self.y2, other.y2)

            
    def addInAdj(self,edge):
        self.inadj.append(edge)
    
    def addOutAdj(self,edge,type):
        """type can be one of:
        Direct = 0
        True = 1
        False = 2
        """
        self.outadj.append((edge,type))
        
    def getOutAdj(self):
        return self.outadj
    
    def getInAdj(self):
        return self.inadj
    
        
    def setName(self,name):
        self.name=name
        
    def getName(self):
        return self.name
    
    def setLabel(self,label):
        self.label=label
    
    def getLabel(self):
        return self.label
    
    def setVertexBuffer(self,buf):
        self.buf=buf
        
    def getVertexBuffer(self):
        return self.buf
    
    def setRelPos(self,x,y):
        self.relx=x
        self.rely=y
        
    def getRelPos(self):
        return (self.relx,self.rely)
    
    def setPlaced(self):
        self.placed=True
    
    def isPlaced(self):
        """returns True if vertex was already placed into the plane"""
        return self.placed
    
    def calculateAbsoluteSize(self,text):
        theight=0
        for line in text:
            (twidth,theight)=debugger.Gettextsize(self.handler,line)
            if twidth > self.absx:
                self.absx=twidth
            self.absy=self.absy+theight
        self.absy=self.absy+4
        self.absx=self.absx+10
        
    
    def getAbsoluteSize(self):
        return (self.absx,self.absy)
    
    def getHeight(self):
        return self.absy
    
    def getWidth(self):
        return self.absx
    
    def getCoords(self):
        self.x2 = self.getWidth() + self.relx
        self.y2 = self.getHeight() + self.rely
        return (self.relx,self.rely,self.x2,self.y2)
    
    def getY2(self):
        return self.y2
    
    def getX(self):
        return self.relx
    
    def getY(self):
        return self.rely
    
    def getX2(self):
        return self.x2
    
    def getCoordsWithMargin(self):
        self.x2 = self.getWidth() + self.relx
        self.y2 = self.getHeight() + self.rely
        return (self.relx,self.rely,self.x2,self.y2)
    
    def setDrawn(self):
        self.drawn=True
    
    def isDrawn(self):
        return self.drawn
    
    def moveNorth(self,value):
        self.rely=self.rely - value
        return
    
    def moveSouth(self,value):
        self.rely=self.rely + value
        return
    
    def moveEast(self,value):
        self.relx = self.relx + value
        return
    
    def moveWest(self,value):
        self.relx = self.relx - value
        return
    
    def placeVertex(self,x,y,text,textcolor,rectcolor,start):
        theight=0
        self.texth=0
        self.textw=0
        f=open("ea.txt","w+")
        for line in text:
            if text.index(line) == 0:
                #title
                (theight,twidth)=debugger.Drawtext(self.handler,x,y+self.texth,line+":",ImmDrawColors["Purple"])
                if twidth > self.textw:
                    self.textw=twidth
                self.texth=self.texth+theight
            else:
                line = line.replace("\x0a","").replace("\x0d","")
                #split asm from comment
                try:
                    asmline=line.split("||")[0]
                    commentline=line.split("||")[1]
                    (theight,twidth)=debugger.Drawtext(self.handler,x,y+self.texth,"  " +asmline,ImmDrawColors[textcolor])
                    (theight,twidth2)=debugger.Drawtext(self.handler,x+twidth,y+self.texth,"  " +commentline,ImmDrawColors["Red"])
                    twidth+=twidth2
                    
                except:
                    (theight,twidth)=debugger.Drawtext(self.handler,x,y+self.texth,"  " +line,ImmDrawColors[textcolor])
                if twidth > self.textw:
                    self.textw=twidth
                self.texth=self.texth+theight
                
        #left    
        debugger.Drawline(self.handler,x-5,y-3,x-5,y+self.texth+2,ImmDrawColors[rectcolor],start) #mark graph start
        #right
        debugger.Drawline(self.handler,x+self.textw+5,y-2,x+self.textw+5,y+self.texth+2,ImmDrawColors[rectcolor])
        #top
        debugger.Drawline(self.handler,x-6,y-3,x+self.textw+5,y-2,ImmDrawColors[rectcolor])
        #bottom
        debugger.Drawline(self.handler,x-6,y+self.texth+2,x+self.textw+5,y+self.texth+2,ImmDrawColors[rectcolor])
        return None
    
    def addEndPoint(x,y,color):
        debugger.Drawline(self.handler,x,y,x,y+3,ImmDrawColors[color])
        debugger.Drawline(self.handler,x,y,x,y-3,ImmDrawColors[color])
        debugger.Drawline(self.handler,x,y,x+3,y+3,ImmDrawColors[color])
        debugger.Drawline(self.handler,x,y,x-3,y+3,ImmDrawColors[color])
        debugger.Drawline(self.handler,x,y,x+3,y-3,ImmDrawColors[color])
        debugger.Drawline(self.handler,x,y,x-3,y-3,ImmDrawColors[color])
        return
    
    def setStartCoords(self,height,width):
        self.start_x=width/2
        self.start_y=10
        
    
    def getStartCoords(self):
        return (self.start_x,self.start_y)

    
    
class Draw:
    def __init__(self):
        """ Initialize the Drawing class"""
        self.title=""
        self.start_address=0
        self.handler=0
        self.edgeproperties=[]
                
    def createGraphWindow(self,title,start_address):
        self.title=title
        self.start_address=int(start_address,16)
        self.handler=debugger.Creategraphwindow(title,self.start_address)
        return self.handler
    
    
    def getTitle(self):
        return self.title
    
    def getHandler(self):
        return self.handler
    
    def setEdgeProperties(self,properties):
        """ properties: { sourcename: "5" ,targetname: "6" ,label: "false", color: red }
        """
        self.edgeproperties.append(properties)
               
        
    def getEdgeProperties(self):
        return self.edgeproperties
        
    

class Line:
    def __init__(self,handler):
        """ Initialize the Line class"""
        self.x_pos=0
        self.y_pos=0
        self.x_to=0
        self.y_to=0
        self.color="Black"
        self.handler=handler
        
    def draw(self,x_pos,y_pos,x_to,y_to,color):
        self.x_pos=x_pos
        self.y_pos=y_pos
        self.x_to=x_to
        self.y_to=y_to
        self.color=color
        return debugger.Drawline(self.handler,self.x_pos,self.y_pos,self.x_to,self.y_to,ImmDrawColors[self.color])
    
            
    def getCoords(self):
        return (self.x_pos,self.y_pos,self.x_to,self.y_to)
    
    def getColor(self):
        return self.color
    
    def getHandle(self):
        return self.handle
    
       

class vcgNode:
    def __init__(self,handler):
        """ Initialize the Recttext class"""
        self.x1=0
        self.y1=0
        self.x2=0
        self.y2=0
        self.rely=0
        self.relx=0
        self.color="Black"
        self.text=""
        self.texth=0
        self.textw=0
        self.absy=0
        self.absx=0
        self.handler=handler
        self.title=""
        self.label=""
        self.nodebuf=[]
        self.child=[]
        
    
    def drawText(self,x,y,text,color):
        debugger.Error("e")
        theight=0
        for line in text:
            #separate asm from comment
            asmline=line.split("||")[0]
            commentline=line.split("||")[1]
            debugger.Error("asm: %s\ncomment: %s" % (asmline,commentline))
            (theight,twidth)=debugger.Drawtext(self.handler,x,y+self.texth,asmline,ImmDrawColors[color])
            (theight,twidth2)=debugger.Drawtext(self.handler,x+twidth,y+self.texth,commentline,ImmDrawColors["Red"])
            twidth+=twidth2
            if twidth > self.textw:
                self.textw=twidth
            self.texth=self.texth+theight
        return None
    
    def drawRect(self,x1,y1,x2,y2,color):
        self.x1=x1
        self.y1=y1
        self.x2=x2
        self.y2=self.y2
        self.color=color
        return debugger.Drawrectangle(self.handler,x1,y1,x2,y2,ImmDrawColors[self.color])
    
    def setTitle(self,title):
        self.title=title
        
    def getTitle(self):
        return self.title
    
    def setLabel(self,label):
        self.label=label
    
    def getLabel(self):
        return self.label
        
    def setNodeBuffer(self,buf):
        self.nodebuf=buf
    
    def getNodeBuffer(self):
        return self.nodebuf
    

        
    def getAbsSize(self,text):
        theight=0
        self.absy=0
        self.absx=0
        for line in text:
            (twidth,theight)=debugger.Gettextsize(self.handler,line)
            if twidth > self.absx:
                self.absx=twidth
            self.absy=self.absy+theight
        return (self.absy+4,self.absx+10)
    
    def setChild(self,child):
        self.child.append(child)
    
    def getChild(self):
        return self.child
    
    def setRelPos(self,x,y):
        self.relx=x
        self.rely=y
        
    def getRelPos(self):
        return (self.relx,self.rely)
