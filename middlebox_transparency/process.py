import os, logging, re, hashlib
from flask import json, jsonify
from state import Transaction, Block

SUCCESS = 1
FAILURE = -1

# The context of the blockchain server
# chain_directory: the directory name of the blockchain directory
# blockchain_list: the list of the chains
class Context:
    def __init__(self, conf_file):
        self.conf_file = conf_file
        self.blockchain_list = []
        
        err = self.init_config()


        if err < 0:
            print ("Error in the configuration file: %s" % self.conf_file)
            print ("Please try again after revising the configuration file")
            exit(-1)

        logging.info("chain_directory: %s" % self.chain_directory)
        logging.info("class_directory: %s" % self.class_directory)

        logging.info("initialize Context finished")

    # Configure the settings
    def init_config(self):
        self.chain_directory = "chains" # Set the default value of the chain directory
        self.class_directory = "class"  # Set the default value of the class directory

        # Set the regular expression to detect the name of the chain
        p = re.compile('\d+[.]')

        chain = None
        with open(self.conf_file, "r") as f:
            skip = False
            for line in f:
                stat = line.strip()
                logging.debug("Statement: %s" % stat)
                if stat.startswith("#"):
                    continue

                if len(stat) == 0:
                    continue

                if p.match(stat):
                    skip = False
                    dot = stat.index(".")
                    num = int(stat[0:dot])
                    chain_id = stat[dot+1:].strip()

                    if num == 0:
                        chain = None
                    else:
                        chain_file = "%s/%s.chain" % (self.chain_directory, chain_id)
                        logging.debug("Chain File Name: %s" % chain_file)

                        if not os.path.exists(chain_file):
                            logging.error("The chain file is not existed: %s" % chain_file)
                            skip = True
                            continue
                        
                        f = open(chain_file, "r")
                        genesis = f.readline()
                        f.close()

                        chain = Block.read_block(chain_id, None, genesis, self)
                        logging.debug(chain.serialize())
                        self.blockchain_list.append(chain)

                elif not skip:
                    if "=" not in stat:
                        pass

                    eq = stat.index("=")
                    key = stat[0:eq].strip()
                    value = stat[eq+1:].strip()

                    logging.debug("key: %s, value: %s" % (key, value))

                    if num == 0:
                        if key is "chain_directory":
                            self.chain_directory = value

                        elif key is "class_directory":
                            self.class_directory = value

        f.close()

        return SUCCESS

    # Get the list of available blockchains
    # Process GET /
    def get_blockchain_list(self):
        if len(self.blockchain_list) > 0:
            for c in self.blockchain_list:
                logging.debug(c.serialize())
            return jsonify(chain_ids=[c.serialize() for c in self.blockchain_list]), 200
        else:
            return jsonify({"error":"No available blockchain is found"}), 404

    # Get the list of available class identifiers
    # Process GET /<chain_id>
    def get_class_list(self, chain_id):
        logging.debug("get_class_list() is invoked")
        fname = "%s/%s.chain" % (self.chain_directory, chain_id)
        cset = set([])

        f = open(fname, "r")
        prev = None

        for curr in f:
            blk = Block.read_block(chain_id, prev, curr, self)

            if blk is None:
                return jsonify({"error": "The block has an error"}), 500

            class_id = blk.get_class_id()
            if len(class_id) > 0:
                cset.add(blk.get_class_id())
            prev = curr

        f.close()

        clst = list(cset)
        if len(clst) > 0:
            return jsonify(available_classess=[{"class_id": c} for c in clst]), 200
        else:
            return jsonify({"error": "No available classe is found"}), 404

    # Make a new blockchain with the name
    # Process POST /<chain_id>
    def make_blockchain(self, chain_id, description):
        cname = "%s.chain" % chain_id
        blk = Block(chain_id, None, None, [], None, None, description)
        blk.set_current_block_hash()
        print ("chain_id: %s" % blk.get_chain_id())
        print ("description: %s" % blk.get_description())
        print ("current block hash: %s" % blk.get_current_block_hash())
        print ("blockchain list: ", self.blockchain_list)

        for c in self.blockchain_list:
            if chain_id == c.get_chain_id():
                return jsonify({'error': 'The chain name is existed.'}), 409

        fname = "%s/%s" % (self.chain_directory, cname)
        line = json.dumps(blk.serialize(), sort_keys = True)
        f = open(fname, "w")
        f.write(line + "\n")
        f.close()
        self.blockchain_list.append(blk)
        return jsonify(blk.serialize()), 200

    # Get the list of available class identifiers
    # Process GET /<chain_id>/<class_id>
    def get_class_time_list(self, chain_id, class_id):
        logging.debug("get_class_time_list() is invoked")

        if class_id == "all":
            return self.show_chain(chain_id, None, None)
            
        fname = "%s/%s.chain" % (self.chain_directory, chain_id)
        cset = set([])

        f = open(fname, "r")
        prev = f.readline()

        for curr in f:
            blk = Block.read_block(chain_id, prev, curr, self)
            if blk.get_class_id() == class_id:
                cset.add(blk.get_class_time())
            prev = curr

        f.close()

        clst = list(cset)

        if len(clst) > 0:
            return jsonify(available_times=[{"class_time": c} for c in clst]), 200
        else:
            return jsonify({"error": "No available class time is found"}), 404
    
    def retrieve_block(self, chain_id, class_id, class_time):
        blks = []
        found = False

        fname = "%s/%s.chain" % (self.chain_directory, chain_id)
        with open(fname, "r") as f:
            prev = f.readline()

            for curr in f:
                blk = Block.read_block(chain_id, prev, curr, self)
                if blk.get_class_id() == class_id and blk.get_class_time() == class_time:
                    found = True
                    blks.append(blk)
                prev = curr

        f.close()

        return blks, found

    def show_chain(self, chain_id, class_id, class_time):
        blks = []
        fname = "%s/%s.chain" % (self.chain_directory, chain_id)
        with open(fname, "r") as f:
            prev = f.readline()

            for curr in f:
                blk = Block.read_block(chain_id, prev, curr, self)
                if class_id:
                    if blk.get_class_id() == class_id:
                        if class_time:
                            if blk.get_class_time() == class_time:
                                blks.append(blk)
                        else:
                            blks.append(blk)
                else:
                    blks.append(blk)
                prev = curr
        f.close()

        return jsonify(blocks=[ b.serialize() for b in blks]), 200


    # Get the block
    # Process GET /<chain_id>/<class_id>/<class_time>
    def get_block(self, chain_id, class_id, class_time):
        logging.debug("get_block() is invoked")
        
        if class_time == "all":
            return self.show_chain(chain_id, class_id, None)
 
        blks, found = self.retrieve_block(chain_id, class_id, class_time)

        logging.debug("number of blocks retrieved: %d" % len(blks))

        if found:
            return jsonify(blocks = [blk.serialize() for blk in blks]), 200
        else:
            return jsonify({"error": "No related block is found"}), 404

    # Make a new block
    # Process POST /<chain_id>/<class_id>/<class_time>
    def make_block(self, chain_id, class_id, class_time, transactions):
        blk = Block(chain_id, class_id, class_time, transactions, self)
        fname = "%s/%s.chain" % (self.chain_directory, chain_id)
        StorageIO.block_commit(fname, blk)
        return jsonify(blk.serialize()), 200

    # Get the information about the student
    # Process GET /<chain_id>/<class_id>/<class_time>/<student_id>
    def get_student(self, chain_id, class_id, class_time, student_id):
        logging.debug("get_student() is invoked")

        blks, found = self.retrieve_block(chain_id, class_id, class_time)

        if not found:
            return jsonify({"error": "No related block is found"}), 404

        found = False

        last_timestamp = 0
        blk = None
        for b in blks[::-1]:
            transactions = b.get_transactions()
            for transaction in transactions:
                if transaction.get_student_id() == student_id:
                    found = True
                    break

            if found == True:
                break

        if found:
            return jsonify(transaction=transaction.serialize()), 200
        else:
            return jsonify({"error": "No related transaction is found"}), 404

# Storage I/O
class StorageIO:
    def _get_last_line(fname):
        logging.info("_get_last_line() is invoked")
        last = None

        with open(fname, "r") as f:
            for last in f:
                pass

        return last

    @classmethod
    def block_commit(self, fname, blk):
        logging.info("block_commit() is invoked")
        logging.info("File name to be added: %s" % fname)
        f = open(fname, "a")

        last = self._get_last_line(fname)
        
        if last:
            tmp = json.loads(last)
            blk.set_previous_block_hash(tmp["current_block_hash"])
            blk.set_current_block_hash()

            f.write(json.dumps(blk.serialize(), sort_keys = True) + "\n")
        f.close()
