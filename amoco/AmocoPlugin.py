# -*- coding: utf-8 -*-
# version 0: POC 

'''
Plugin IDA qui une fois copié dans le repertoire
plugins d'IDA est accessible depuis le menu 
Edit --> plugins 
'''

from idaapi import *
import amoco

class MyGraph(GraphViewer):
	def __init__(self, flow_graph,title):
		GraphViewer.__init__(self, title)
		print '[+] Flow Graph (GraphViewer Class) init'
		self._title = title
		self.SetCurrentRendererType(idaapi.TCCRT_GRAPH)
		self.flow_graph = flow_graph
		#self.result = result
		#self.names = {}
        
	def OnRefresh(self):
		print 'refresh'
		self.Clear()
		addr_in = {}
		test = idaapi.COLSTR("test0	test2	",idaapi.SCOLOR_INSN)
		self.AddNode(test)
		for i in self.flow_graph:
			id = self.AddNode(i)
			
		return True


	def OnSelect(self,node_id):
		print("OnSelect Event .")
		#self.Select(node_id)
		return True

	def OnClick(self,node_id):
		print("OnClick() Event .")
		#print self[node_id]
		print self
		print self._title
		frm = idaapi.find_tform(self._title)
		print frm
		#self.Select(node_id)
		return True

	def OnGetText(self, node_id):
		#self.Refresh()
		return str(self[node_id])

	def OnCommand(self,cmd_id):
		if self.cmd_test == cmd_id:
			print("Amoco : Symbolic form ")
                        # access flow graph blocks and print their symbolic form
                        fl = list() 
                        for node in self.flow_graph:
                            idaapi.msg(" Symbolic form is \n %s \n"%node.map)
                            fl.append(node.map)
                        
                        for i in fl:
                            self.flow_graph.append(i)
                        self.Refresh() 

			return
		if self.cmd_test2 == cmd_id:
			print("Amoco Menu :  Item2")
			return
		print("command :%s",cmd_id)

	def Show(self):
	
		if not GraphViewer.Show(self):
			return False
		self.cmd_test  = self.AddCommand("Amoco Menu :  Symbolic form","F2")
		self.cmd_test2 = self.AddCommand("Amoco Menu :  Item2","F3")

		if self.cmd_test == 0 :
			print("Failed to add popup menu Item1 !")
		if self.cmd_test2 == 0:
			print("Failed to add popup menu Item2 !")
		return True




#Configuration Handler
class HTooltipC(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idaapi.warning("Configuration : Tooltip-providing action triggered")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


#Analyse Handler 
class HTooltipDisassemble(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        idaapi.warning("Disassemble : Tooltip-providing action triggered")
        idaapi.msg(" Disassemble handler %s \n"%type(ctx))
        idaapi.msg(" Disassemble handler current ea %s \n"%hex(ctx.cur_ea).rstrip('L'))
        amocoform = idaapi.get_current_tform() 
        idaapi.msg(" Disassemble current form is %s\n"%idaapi.get_tform_title(amocoform))
        idaapi.msg(" Disassemble current form type is %s\n"%idaapi.get_tform_type(amocoform))
        highlighted_item = "None"
        #highlighted_item = idaapi.get_highlighted_identifier() 

        if (idaapi.get_tform_title(amocoform) == "IDA View Amoco Plugin" ):
            if ( idaapi.get_tform_type(amocoform) == 29 ) : 
                highlighted_item = idaapi.get_highlighted_identifier() 

        idaapi.msg(" Disassemble current selected item %s\n"% highlighted_item) 

        # get the path the analyzed file to pass it to amoco 
        filename =  GetInputFilePath() 
        pe  =  amoco.system.loader.load_program(filename)

        # get start and end selection 
        start_selection  = hex(SelStart()) 
        end_selection = hex(SelEnd())
        idaapi.msg(" Start selection  : %s - End selection : %s\n"%(start_selection,end_selection) )  
        
        # apply lbackward algo 
        z = amoco.lbackward(pe)

        # get selected block 
        block =  z.getblock(SelStart())
        idaapi.msg(" Amoco disassembly is \n %s \n"% block)
 
        # create a new graph view for Amoco 
        flow_graph = list()
        flow_graph.append(block)
        g = MyGraph(flow_graph,"Amoco Flow Graph")
        g.Show()
  
  

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS



class Hooks(idaapi.UI_Hooks):
    def populating_tform_popup(self, form, popup):
        idaapi.msg("Hooks called\n")
        idaapi.attach_action_to_popup(form, popup, "my:tooltip0", "Amoco/Config/", idaapi.SETMENU_APP)
        idaapi.attach_action_to_popup(form, popup, "my:tooltip1", "Amoco/Analyse/", idaapi.SETMENU_APP)


class amoco_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Amoco is really cool ! "

    help = "This is help"
    wanted_name = "Amoco IDA Plugin"
    wanted_hotkey = "Alt-F8"
    hooks = None 

    def init(self):
        idaapi.msg("init() called!\n")
        self.hooks = Hooks()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)
        tooltip_act0 = idaapi.action_desc_t('my:tooltip0', 'Amoco : Configuration ', HTooltipC(), '', 'This is a tooltip-providing action tooltip', -1)
        tooltip_act1 = idaapi.action_desc_t('my:tooltip1', 'Amoco : Disassemble ', HTooltipDisassemble(), '', 'This is yet another a tooltip-providing action tooltip', -1)
        idaapi.register_action(tooltip_act0)
        idaapi.register_action(tooltip_act1)
        idaapi.attach_action_to_menu("View/", 'my:tooltip0', idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("View/", 'my:tooltip1', idaapi.SETMENU_APP)

        # we give the focus to IDA View-A 
        ida_view_a_form =  idaapi.find_tform("IDA View-A")
        idaapi.switchto_tform(ida_view_a_form,1)
        idaapi.open_disasm_window("Amoco Plugin ")

        #hooks = Hooks()
        idaapi.msg("Calling Hooks\n")
        self.hooks.hook()

    def term(self):
        idaapi.msg("term() called!\n")
        if self.hooks is not None :
            self.hooks.unhook()
            self.hooks =  None 
    
        #TO DO unhook actions 

def PLUGIN_ENTRY():
    return amoco_plugin_t()

