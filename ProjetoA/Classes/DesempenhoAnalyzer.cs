using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Windows.Foundation.Metadata;

public class DesempenhoAnalyzer
{
    delegate void AnaliseDesempenho(SyntaxTree syntaxTree, Dictionary<string, int[]> findings);

    public async Task<StringBuilder> AnalyzeCodeAsync(SyntaxTree syntaxTree)
    {
        AnaliseDesempenho[] analisesDesempenho =
        {
            AnalyzeUnnecessaryObjectCreation,
            AnalyzeInefficientDataStructures,
            AnalyzeLackOfInputValidation,
            AnalyzeExcessiveUseOfExceptions,
            AnalyzeInefficientStringConcatenation,
            AnalyzeNotDisposingOfResources,
            AnalyzeNotUsingAsynchronousProgramming,
        };

        // Create a list to store the findings
        var findings = new Dictionary<string, int[]>();

        // Analyze the code for each pattern
        List<Task> tasks = new List<Task>();

        for(int i = 0; i < analisesDesempenho.Count(); i++)
        {
            tasks.Add(Task.Run(() => analisesDesempenho[i](syntaxTree,findings)));
        }

        await Task.WhenAll(tasks);

        // Save the findings to an HTML table
        StringBuilder table = new StringBuilder(null);

        if (findings.Count() <= 0)
        {
            return await Task.FromResult(table);
        }

        table.AppendLine("<table>");
        table.AppendLine("<tr><th>Pattern Name</th><th>Line Numbers</th></tr>");
        table.AppendLine("<tr>");

        foreach (var finding in findings)
        {
            table.Append($"<td>{finding.Key}</td><td>");

            for (int i = 0; i < finding.Value.Count(); i++)
            {
                table.Append($"{finding.Value[i]}");

                if (i + 1 < finding.Value.Count())
                {
                    table.Append(',');
                }
            }

            table.Append("</td></tr>");
        }

        table.AppendLine("</table>");

        return await Task.FromResult(table);
    }

    void AnalyzeUnnecessaryObjectCreation(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var objectCreationExpressions = syntaxTree.GetRoot().DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
        foreach (var expression in objectCreationExpressions)
        {
            if (IsUnnecessaryObjectCreation(expression))
            {
                findings["Unnecessary object creation"] = findings.TryGetValue("Unnecessary object creation", out var lines)
                ? lines.Concat(new[] { expression.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
                : new[] { expression.GetLocation().GetLineSpan().StartLinePosition.Line +1 };
            }
        }
    }
    void AnalyzeInefficientDataStructures(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var dataStructureDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<VariableDeclarationSyntax>();
        foreach (var declaration in dataStructureDeclarations)
        {
            if (IsInefficientDataStructure(declaration))
            {
                findings["Inefficient data structure"] = findings.TryGetValue("Inefficient data structure", out var lines)
                ? lines.Concat(new[] { declaration.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
                : new[] { declaration.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeLackOfInputValidation(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var methodDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methodDeclarations)
        {
            if (IsLackOfInputValidation(method))
            {
               findings["Lack of input validation"] = findings.TryGetValue("Lack of input validation", out var lines)
               ? lines.Concat(new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeExcessiveUseOfExceptions(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var throwStatements = syntaxTree.GetRoot().DescendantNodes().OfType<ThrowStatementSyntax>();
        foreach (var statement in throwStatements)
        {
            if (IsExcessiveUseOfExceptions(statement))
            {
               findings["Excessive use of exceptions"] = findings.TryGetValue("Excessive use of exceptions", out var lines)
               ? lines.Concat(new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeInefficientStringConcatenation(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var stringConcatenations = syntaxTree.GetRoot().DescendantNodes().OfType<InterpolatedStringContentSyntax>();
        foreach (var concatenation in stringConcatenations)
        {
            if (IsInefficientStringConcatenation(concatenation))
            {
               findings["Inefficient string concatenation"] = findings.TryGetValue("Inefficient string concatenation", out var lines)
               ? lines.Concat(new[] { concatenation.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
               : new[] { concatenation.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeNotDisposingOfResources(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var usingStatements = syntaxTree.GetRoot().DescendantNodes().OfType<UsingStatementSyntax>();
        foreach (var statement in usingStatements)
        {
            if (IsNotDisposingOfResources(statement))
            {
              findings["Não disposição de recursos"] = findings.TryGetValue("Não disposição de recursos", out var lines)
              ? lines.Concat(new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
              : new[] { statement.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }
    void AnalyzeNotUsingAsynchronousProgramming(SyntaxTree syntaxTree, Dictionary<string, int[]> findings)
    {
        var methodDeclarations = syntaxTree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methodDeclarations)
        {
            if (IsNotUsingAsynchronousProgramming(method))
            {
              findings["Não utlização de programação assíncrona"] = findings.TryGetValue("Não utlização de programação assíncrona", out var lines)
              ? lines.Concat(new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 }).ToArray()
              : new[] { method.GetLocation().GetLineSpan().StartLinePosition.Line + 1 };
            }
        }
    }

    bool IsUnnecessaryObjectCreation(ObjectCreationExpressionSyntax expression)
    {
        // Check if the object is immediately assigned to a variable
        if (expression.Parent is AssignmentExpressionSyntax assignment)
        {
            var variable = assignment.Left as IdentifierNameSyntax;
            if (variable != null)
            {
                // Check if the variable is used only once as a standalone statement
                var usages = expression.SyntaxTree.GetRoot().DescendantNodes().OfType<IdentifierNameSyntax>()
                   .Where(id => id.Identifier.ValueText == variable.Identifier.ValueText);
                var standaloneUsages = usages.Where(id => id.Parent is ExpressionStatementSyntax);
                if (standaloneUsages.Count() == 1)
                {
                    return true; // Unnecessary object creation
                }
            }
        }
        
        else
        {
            // Check if the object is not used anywhere in the code
            var usages = expression.SyntaxTree.GetRoot().DescendantNodes().OfType<ObjectCreationExpressionSyntax>()
               .Where(oc => oc == expression);
            if (!usages.Any())
            {
                return true; // Unnecessary object creation
            }

            // Check if the object creation occurs in unnecessary loops
            ForStatementSyntax containingLoop = expression.Ancestors().OfType<ForStatementSyntax>().FirstOrDefault();
            
            if (containingLoop == null)
            {
               ForEachStatementSyntax containingLoop2 = expression.Ancestors().OfType<ForEachStatementSyntax>().FirstOrDefault();

                if(containingLoop2 != null && (!containingLoop2.DescendantNodes().OfType<ObjectCreationExpressionSyntax>().Contains(expression)))
                {
                    return true;
                }
            }
            
            else if (containingLoop != null && (!containingLoop.DescendantNodes().OfType<ObjectCreationExpressionSyntax>().Contains(expression)))
            {
                return true; // Unnecessary object creation
            }
        }

        return false;
    }
    bool IsInefficientDataStructure(VariableDeclarationSyntax declaration)
    {
        var initializer = declaration.Parent as EqualsValueClauseSyntax;
        if (initializer != null)
        {
            var objectCreation = initializer.Parent as ObjectCreationExpressionSyntax;
            if (objectCreation != null)
            {
                var type = objectCreation.Type;
                if (type is IdentifierNameSyntax identifierName)
                {
                    var typeName = identifierName.Identifier.ValueText;
                    // Check if the type is an inefficient data structure
                    switch (typeName)
                    {
                        case "ArrayList":
                        case "Hashtable":
                        case "Queue":
                        case "Stack":
                        case "ConcurrentDictionary":
                            // These are considered inefficient data structures
                            return true;
                        default:
                            // Other types are not considered inefficient
                            return false;
                    }
                }
            }
        }
        return false;
    }
    bool IsLackOfInputValidation(MethodDeclarationSyntax method)
    {
        // Verificar se o método tem parâmetros
        if (method.ParameterList.Parameters.Count == 0)
        {
            return false; // Se não tiver parâmetros, não há input para validar
        }

        // Verificar se há alguma lógica de validação de entrada no corpo do método
        var methodBody = method.Body;
        if (methodBody == null)
        {
            return true; // Se o método não tiver corpo, assume-se que não há validação de entrada
        }

        // Verificar se há chamadas a métodos de validação de entrada
        var validationMethods = new[] { "string.IsNullOrEmpty", "int.TryParse", "long.TryParse", "bool.TryParse", "double.TryParse", "DateTime.TryParse" };
        var validationCalls = methodBody.DescendantNodes().OfType<InvocationExpressionSyntax>()
            .Select(invocation => invocation.Expression.ToString())
            .Any(expression => validationMethods.Any(m => expression.Contains(m)));

        if (validationCalls)
        {
            return false; // Se há chamadas a métodos de validação de entrada, assume-se que há validação de entrada
        }

        // Verificar se há verificações de condição de validação de entrada
        var conditionals = methodBody.DescendantNodes().OfType<BinaryExpressionSyntax>()
            .Where(binaryExpression => binaryExpression.IsKind(SyntaxKind.EqualsExpression) || binaryExpression.IsKind(SyntaxKind.NotEqualsExpression))
            .Select(binaryExpression => (binaryExpression.Left, binaryExpression.Right))
            .Any(pair => pair.Left is IdentifierNameSyntax identifier &&
                         method.ParameterList.Parameters.Any(parameter => parameter.Identifier.Text == identifier.Identifier.Text) &&
                         pair.Right.IsKind(SyntaxKind.NullLiteralExpression));

        if (conditionals)
        {
            return false; // Se há uma verificação de condição que checa se o input é nulo, assume-se que há validação de entrada
        }

        // Se não há nenhuma lógica de validação de entrada, retorna true
        return true;
    }
    bool IsExcessiveUseOfExceptions(ThrowStatementSyntax statement)
    {
        var parent = statement.Parent;
        while (parent != null)
        {
            if (parent is TryStatementSyntax)
            {
                var tryBlock = (TryStatementSyntax)parent;
                // Check for empty try block
                if (tryBlock.Block.Statements.Count == 0)
                {
                    return true;
                }
                // Check for try blocks with no catch clauses
                if (tryBlock.Catches.Count == 0)
                {
                    var expression = statement.Expression;
                    if (expression is ObjectCreationExpressionSyntax objectCreation)
                    {
                        var typeName = objectCreation.Type.ToString();
                        // Check for specific exception types
                        if (typeName == "Exception" || typeName == "ApplicationException")
                        {
                            return true;
                        }
                        // Add checks for more specific exception types if needed
                    }
                    // Check for throw statements without exception type (re-throw)
                    else if (expression == null)
                    {
                        return true;
                    }
                }
                break;
            }
            parent = parent.Parent;
        }
        return false;
    }
    bool IsInefficientStringConcatenation(InterpolatedStringContentSyntax concatenation)
    {
        // Verificar se a concatenação ocorre dentro de um loop
        var parent = concatenation.Parent;
        while (parent != null)
        {
            if (parent is ForStatementSyntax || parent is WhileStatementSyntax || parent is DoStatementSyntax || parent is ForEachStatementSyntax)
            {
                return true;
            }
            parent = parent.Parent;
        }

        // Verificar se a concatenação envolve muitas operações de concatenação
        var expressions = concatenation.DescendantNodes().OfType<BinaryExpressionSyntax>();
        var concatenationCount = 0;
        foreach (var expression in expressions)
        {
            if (expression.OperatorToken.IsKind(SyntaxKind.PlusToken))
            {
                concatenationCount++;
            }
        }

        if (concatenationCount > 3) // ajuste o valor de acordo com a sua necessidade
        {
            return true;
        }
        
        // Verificar se a concatenação envolve uma string literal longa
        var literals = concatenation.DescendantNodes().OfType<LiteralExpressionSyntax>();
        foreach (var literal in literals)
        {
            if (literal.IsKind(SyntaxKind.StringLiteralExpression) && literal.Token.ValueText.Length > 50) // ajuste o comprimento conforme necessário
            {
                return true;
            }
        }

        return false;
    }
    bool IsNotDisposingOfResources(UsingStatementSyntax statement)
    {
        // Verifica se há declarações de variáveis dentro do bloco using
        var declaration = statement.Declaration;
        if (declaration != null)
        {
            foreach (var variable in declaration.Variables)
            {
                // Verifica se a variável não está sendo inicializada com null
                if (!variable.Initializer.Value.IsKind(SyntaxKind.NullLiteralExpression))
                {
                    return true; // Recurso não está sendo descartado corretamente
                }
            }
        }

        // Verifica se há expressões de recurso no bloco using
        var expression = statement.Expression;
        if (expression != null)
        {
            // Verifica se a expressão não é nula
            if (!expression.IsKind(SyntaxKind.NullLiteralExpression))
            {
                return true; // Recurso não está sendo descartado corretamente
            }

            // Verifica se a expressão é uma chamada de método
            if (expression is InvocationExpressionSyntax invocation)
            {
                // Verifica se o método chamado é um método de abertura de arquivo, como File.Open()
                var methodName = invocation.Expression.ToString();
                if (methodName.Equals("File.Open"))
                {
                    return true; // Recurso não está sendo descartado corretamente
                }
            }
        }

        return false; // Não foram encontrados problemas de falta de disposição de recursos
    }
    bool IsNotUsingAsynchronousProgramming(MethodDeclarationSyntax method)
    {
        var methodBody = method.Body;
        if (methodBody == null)
        {
            // Se o método não tem corpo, não pode usar programação assíncrona
            return false;
        }

        // Verifica se há chamadas assíncronas dentro do corpo do método
        var asyncCalls = methodBody.DescendantNodes().OfType<InvocationExpressionSyntax>()
            .Any(invocation => invocation.Expression is IdentifierNameSyntax identifier &&
                                identifier.Identifier.Text.EndsWith("Async"));

        return !asyncCalls;
    }
}