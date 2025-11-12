-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- NumbersToExpressions.lua

unpack = unpack or table.unpack

local Step = require("prometheus.step")
local Ast = require("prometheus.ast")
local visitast = require("prometheus.visitast")
local util = require("prometheus.util")

local AstKind = Ast.AstKind

local NumbersToExpressions = Step:extend()
NumbersToExpressions.Description = "This Step Converts number Literals to Expressions"
NumbersToExpressions.Name = "Numbers To Expressions"

NumbersToExpressions.SettingsDescriptor = {
	Treshold = {
        type = "number",
        default = 3,
        min = 0,
        max = 1,
    },
    InternalTreshold = {
        type = "number",
        default = 0.2,
        min = 0,
        max = 0.8,
    }
}

function NumbersToExpressions:init(settings)
    self.ExpressionGenerators = {
        function(val, depth) -- Multiplication
            if val == 0 then
                return Ast.NumberExpression(0)
            end
            local max_factor = 128
            for _ = 1, 10 do
                local factor = math.random(1, max_factor)
                if math.abs(val) % factor == 0 then
                    local other = val / factor
                    if tonumber(tostring(factor)) * tonumber(tostring(other)) == val then
                        return Ast.MulExpression(
                            self:CreateNumberExpression(factor, depth),
                            self:CreateNumberExpression(other, depth),
                            false
                        )
                    end
                end
            end
            return false
        end,
        function(val, depth) -- Division
            if val == 0 then
                return Ast.NumberExpression(0)
            end
            local max_factor = 128
            for _ = 1, 10 do
                local divisor = math.random(1, max_factor)
                local numerator = val * divisor
                if tonumber(tostring(numerator)) / tonumber(tostring(divisor)) == val then
                    return Ast.DivExpression(
                        self:CreateNumberExpression(numerator, depth),
                        self:CreateNumberExpression(divisor, depth),
                        false
                    )
                end
            end
            return false
        end
    }
end

function NumbersToExpressions:CreateNumberExpression(val, depth)
    if depth > 0 and math.random() >= self.InternalTreshold or depth > 15 then
        return Ast.NumberExpression(val)
    end

    local generators = util.shuffle({unpack(self.ExpressionGenerators)})
    for _, generator in ipairs(generators) do
        local node = generator(val, depth + 1)
        if node then
            return node
        end
    end

    return Ast.NumberExpression(val)
end

-- Recursively try to evaluate constant math expressions
function NumbersToExpressions:evaluateIfConstant(node)
    if not node then return nil end

    if node.kind == AstKind.NumberExpression then
        return node.value
    elseif node.kind == AstKind.MulExpression or node.kind == AstKind.DivExpression then
        local left = self:evaluateIfConstant(node.left)
        local right = self:evaluateIfConstant(node.right)
        if left and right then
            if node.kind == AstKind.MulExpression then
                return left * right
            elseif node.kind == AstKind.DivExpression then
                return right ~= 0 and left / right or nil
            end
        end
    end

    return nil
end

function NumbersToExpressions:apply(ast)
	visitast(ast, nil, function(node, data)
        -- Apply to raw number literals
        if node and node.kind == AstKind.NumberExpression then
            if math.random() <= self.Treshold then
                return self:CreateNumberExpression(node.value, 0)
            end
        end

        -- Also apply to constant binary math expressions (like 3/3 or 4*2)
        if node and (node.kind == AstKind.MulExpression or node.kind == AstKind.DivExpression) then
            local value = self:evaluateIfConstant(node)
            if value and math.random() <= self.Treshold then
                return self:CreateNumberExpression(value, 0)
            end
        end
    end)
end

return NumbersToExpressions
