import re

class QueryParser:
    """
    Safely tokenizes and builds an AST for threat hunting queries without using eval.
    Supports: AND, OR, ==, !=, >, <, IN, (), ''
    Example: process_name == 'powershell.exe' AND severity == 'HIGH'
    """
    
    def __init__(self):
        # We split by AND / OR carefully or build a fast recursive descent parser.
        # Given Python's limits, an iterative shunting-yard or simple recursive descent is best.
        
        # simple tokenize regex
        self.token_pat = re.compile(
            r'\s*(?:(AND|OR)|(==|!=|>=|<=|>|<|IN|in)|(\(|\))|([a-zA-Z_]\w*)|(\'(?:[^\']|(?<=\\)\')*\'|"(?:[^"]|(?<=\\)")*")|([^ \t\n\r\f\v()]+))\s*', 
            re.IGNORECASE
        )

    def tokenize(self, query: str):
        pos = 0
        tokens = []
        while pos < len(query):
            match = self.token_pat.match(query, pos)
            if not match:
                if query[pos].strip():
                    raise ValueError(f"Unexpected character at pos {pos}: {query[pos]}")
                pos += 1
                continue
            
            logic_op, cmp_op, paren, ident, string_val, other = match.groups()
            
            if logic_op: tokens.append(("LOGIC", logic_op.upper()))
            elif cmp_op: tokens.append(("OP", cmp_op.upper()))
            elif paren: tokens.append(("PAREN", paren))
            elif ident: tokens.append(("IDENT", ident))
            elif string_val: tokens.append(("STRING", string_val[1:-1])) # strip quotes
            elif other: 
                # might be a number
                try: 
                    tokens.append(("NUMBER", float(other)))
                except:
                    tokens.append(("OTHER", other))
                    
            pos = match.end()
        return tokens

    def parse(self, query: str):
        """ Returns AST dictionary. """
        tokens = self.tokenize(query)
        if not tokens: return {}

        # Super simplified parser for (A AND B OR C).
        # We'll build a postfix expression stack and evaluate it.
        # Due to complexity limitations, we translate tokens -> Dict conditions.
        
        # Using a simple iterative group mechanism
        return self._parse_tokens(tokens)

    def _parse_tokens(self, tokens: list):
        # We will parse conditions: IDENT OP VALUE
        idx = 0
        def parse_primary():
            nonlocal idx
            if idx >= len(tokens):
                return None
            
            token = tokens[idx]
            if token[0] == "PAREN" and token[1] == "(":
                idx += 1
                node = parse_expr()
                if idx < len(tokens) and tokens[idx][0] == "PAREN" and tokens[idx][1] == ")":
                    idx += 1
                return node
                
            if token[0] == "IDENT":
                field = token[1]
                idx += 1
                if idx < len(tokens) and tokens[idx][0] == "OP":
                    op = tokens[idx][1]
                    idx += 1
                    if idx < len(tokens) and tokens[idx][0] in ("STRING", "NUMBER", "IDENT", "OTHER"):
                        val = tokens[idx][1]
                        idx += 1
                        
                        # Fix for list string splits if OP is IN
                        if op == "IN" and isinstance(val, str):
                            val = [v.strip() for v in val.split(",")]
                            
                        return {"type": "condition", "field": field, "op": op, "value": val}
            return None

        def parse_and():
            nonlocal idx
            left = parse_primary()
            while idx < len(tokens) and tokens[idx][0] == "LOGIC" and tokens[idx][1] == "AND":
                idx += 1
                right = parse_primary()
                left = {"type": "logic", "op": "AND", "left": left, "right": right}
            return left

        def parse_expr():
            nonlocal idx
            left = parse_and()
            while idx < len(tokens) and tokens[idx][0] == "LOGIC" and tokens[idx][1] == "OR":
                idx += 1
                right = parse_and()
                left = {"type": "logic", "op": "OR", "left": left, "right": right}
            return left

        ast = parse_expr()
        return ast
